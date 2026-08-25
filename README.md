# DNS-Maintenance

`DNS-Maintenance` — центральный движок для автоматического обслуживания списков DNS-имён в GitHub-репозиториях.

Результат работы системы можно посмотреть на странице **[Service Lists](https://dkhnv.github.io/Service-Lists/index.html)** — там собраны актуальные списки, которые поддерживаются автоматикой.

Задача движка довольно простая: DNS-список должен оставаться полезным со временем, а не превращаться в склад старых записей, временных ошибок DNS, внутренних адресов и hostname, которые когда-то существовали и с тех пор тихо умерли.

Движок умеет:

- находить новые hostname;
- проверять уже известные через несколько DNS-resolver'ов;
- принимать только публичные IPv4;
- постепенно выводить неактуальные записи из эксплуатации;
- семантически исключать неподходящие hostname;
- отдельно наблюдать HTTPS/TLS;
- принимать Runtime Candidate Feed от внешнего наблюдателя;
- сохранять состояние между запусками;
- формировать отчёты.

При этом система намеренно сделана консервативной: одно неудачное наблюдение не является достаточным основанием что-либо удалять или публиковать.

## Как это работает

Основной Exact DNS pipeline выглядит так:

```text
Discovery
   ↓
Нормализация hostname
   ↓
Проверка через несколько DNS-resolver'ов
   ↓
Фильтрация IPv4
   ↓
DNS lifecycle
   ↓
Hostname Policy
   ↓
Актуальный публичный DNS-список
   ↓
Отдельная проверка HTTPS/TLS
   ↓
State + отчёт
```

Отдельно существует Runtime Candidate Intake:

```text
Runtime_Candidate_Feed.json
   ↓
Независимая валидация
   ↓
Runtime Candidate state
```

Эти два канала намеренно разделены.

Runtime Candidate из внешнего наблюдения **не становится автоматически Exact DNS-кандидатом**, не передаётся в `maintain_dns()` и не публикуется в `*_DNS`.

Сам движок хранится в центральном репозитории, а каждый сервисный репозиторий содержит собственную конфигурацию, публичный DNS-файл и рабочее состояние.

Стандартное имя конфигурации:

```text
dns-maintenance-v1.json
```

## Поиск новых hostname

Discovery может получать новые имена из Certificate Transparency через Cert Spotter.

Для каждой коллекции задаются корневые домены, после чего движок постепенно просматривает историю сертификатов и сохраняет позицию, на которой остановился. Большой объём данных не требуется обрабатывать за один запуск.

Wildcard-записи вроде:

```text
*.example.com
```

не добавляются как готовые hostname.

Найденное конкретное имя сначала становится кандидатом и только после DNS-проверки может попасть в активный список.

Кроме автоматического discovery поддерживаются очереди:

```text
manual.txt
discovered.txt
```

`manual.txt` предназначен для вручную добавленных hostname.

`discovered.txt` позволяет передать Exact DNS-кандидаты из внешнего источника.

После обычного production-запуска содержимое этих очередей импортируется в state и очищается.

## Проверка DNS

Каждый hostname проверяется через несколько независимых DNS-resolver'ов.

По умолчанию используются:

```text
1.1.1.1
8.8.8.8
9.9.9.9
```

Результат сводится к одному из трёх состояний:

- `OK` — найден хотя бы один подходящий публичный IPv4;
- `NEGATIVE` — достаточное число resolver'ов подтвердило отрицательный результат;
- `TRANSIENT` — уверенного результата нет, например из-за временной ошибки или таймаута.

`TRANSIENT` не ухудшает lifecycle hostname.

Временный сетевой сбой не должен превращаться в автоматическое удаление записи.

### Фильтрация IPv4

A-запись сама по себе ещё не означает, что адрес подходит для публичного сетевого списка.

Движок принимает только публичные unicast IPv4.

Внутренние, зарезервированные, multicast и другие non-global адреса отбрасываются.

Если hostname одновременно имеет публичные и неподходящие A-записи, для проверки и дальнейшей работы сохраняются только публичные адреса.

Если ранее опубликованный hostname подтверждён несколькими resolver'ами как имеющий только non-global A-записи, он сразу отправляется в `quarantine`.

Такой случай считается проблемой безопасности публичного списка и не ждёт обычного периода деградации.

## DNS lifecycle

Удаление сделано через lifecycle, а не по принципу «один раз не ответил — удалить».

Базовая последовательность:

```text
pending → active → suspect → quarantine → expired
             ↑         │
             └─────────┘
            успешный DNS
```

Отдельно существует семантическое состояние:

```text
excluded
```

Оно управляется Hostname Policy и не является DNS quarantine.

### `pending`

Новый hostname, который ещё не был подтверждён DNS-проверкой.

После успешной проверки становится `active`.

### `active`

Нормальная рабочая запись.

Если DNS начинает стабильно возвращать подтверждённый отрицательный результат, запускается окно наблюдения.

### `suspect`

Hostname достаточно долго и достаточное число раз даёт отрицательный DNS-результат.

Он всё ещё остаётся в публичном списке.

Это дополнительная страховка от временных проблем DNS, изменений инфраструктуры и неудачного момента проверки.

Успешный DNS-ответ возвращает его в `active`.

### `quarantine`

Если отрицательное состояние сохраняется достаточно долго и набрано необходимое число наблюдений, hostname переносится в карантин и исчезает из публичного активного списка.

Если позже DNS снова становится нормальным, запись может вернуться в `active`.

### `expired`

Если hostname достаточно долго остаётся в карантине, он переходит в `expired`.

Запись не забывается полностью.

Если discovery снова найдёт этот hostname, он вернётся в `pending` и должен будет пройти проверку заново.

### `excluded`

`excluded` используется Hostname Policy для hostname, которые технически могут иметь рабочий DNS, но не должны входить в публичный список по семантическим причинам.

Например:

- test;
- staging;
- development;
- internal;
- sandbox;
- другие явно исключённые namespace.

`excluded` не является DNS quarantine и не ослабляет DNS safety rules.

## Hostname Policy

Hostname Policy — отдельный семантический слой после DNS validation.

Упрощённая последовательность:

```text
DNS validation
   ↓
Hostname Policy
   ↓
HTTPS/TLS observation
```

Policy поддерживает правила:

```text
exact
suffix
```

Suffix matching выполняется по границе DNS-имени.

Например, правило:

```text
test.example.com
```

может соответствовать:

```text
test.example.com
api.test.example.com
```

но не:

```text
notest.example.com
```

Пример конфигурации:

```json
{
  "hostname_policy": {
    "enabled": true,
    "allow": [
      {
        "id": "keep-required-host",
        "match": "exact",
        "value": "required.example.com",
        "reason": "Required service endpoint"
      }
    ],
    "exclude": [
      {
        "id": "drop-test-environment",
        "match": "suffix",
        "value": "test.example.com",
        "reason": "Non-production environment"
      }
    ]
  }
}
```

Приоритеты:

1. DNS safety states `quarantine` и `expired` имеют более высокий приоритет, чем semantic policy.
2. Ручной источник может обойти semantic exclusion, но не может обойти DNS safety.
3. `allow` является исключением из более широкого `exclude`.
4. Не совпавший ни с одним правилом hostname разрешён.

После снятия semantic exclusion hostname не публикуется бездумно обратно.

Для возвращения в `active` требуется актуальное подтверждение DNS.

## Runtime Candidate Intake

Кроме Exact DNS discovery движок может принимать отдельный Runtime Candidate Feed, сформированный внешним наблюдателем, например Service Router.

Feed располагается в корне caller-репозитория:

```text
Runtime_Candidate_Feed.json
```

Runtime Candidate Intake включается отдельно для каждой коллекции:

```json
{
  "runtime_candidate": {
    "enabled": true
  }
}
```

По умолчанию:

```json
{
  "runtime_candidate": {
    "enabled": false
  }
}
```

То есть существующие сервисы не начинают обрабатывать Runtime Candidate Feed только из-за обновления центрального движка.

### Что проверяется

Перед приёмом Feed выполняется независимая валидация.

Проверяются в том числе:

- версия схемы;
- имя сервиса;
- UUID наблюдателя;
- область истории;
- алгоритм и значение content hash;
- уникальность candidate ID;
- формула candidate ID;
- hostname;
- suffix;
- принадлежность hostname к suffix;
- состояние кандидата;
- типы счётчиков и метрик;
- отсутствие запрещённых raw routing-полей.

Runtime Candidate Feed не должен переносить в DNS-Maintenance сырые routing-данные вроде:

```text
ipv4
ipv4_seen
network
networks_seen
cidr
ttl
ttl_min
ttl_max
last_ttl_min
last_ttl_max
```

### Где хранится состояние

После успешной проверки Runtime Candidate state сохраняется внутри data directory коллекции:

```text
dns/<service>/runtime_candidate_state.json
```

Он хранит историю независимо от Exact DNS lifecycle.

### Важная граница

Факт наблюдения hostname в реальном трафике означает только одно: внешний observer этот hostname видел.

Он **не означает автоматически**, что hostname:

- должен быть добавлен в `pending`;
- должен стать `active`;
- должен появиться в `*_DNS`;
- является Routing Suffix;
- должен влиять на маршрутизацию.

Runtime Candidate Intake v1 занимается только безопасным приёмом, проверкой и хранением наблюдений.

Автоматического promotion в Exact DNS в v1 нет.

### Ошибки Feed

Если Feed:

- отсутствует;
- содержит повреждённый JSON;
- имеет неизвестную схему;
- не проходит проверку hash;
- содержит неправильный service;
- содержит запрещённые данные;
- содержит другую ошибку контракта;

предыдущее Runtime Candidate state не уничтожается.

Ошибка Runtime Candidate Intake также не должна останавливать обычный Exact DNS pipeline.

### Dry run

При `--dry-run` Feed:

1. читается;
2. валидируется;
3. prospective state вычисляется;
4. файл `runtime_candidate_state.json` не записывается.

## HTTPS/TLS проверяется отдельно

После DNS-проверки движок может дополнительно проверить HTTPS/TLS для активных hostname.

Проверяется:

- TCP-соединение;
- TLS;
- HTTP-ответ;
- несколько доступных публичных IPv4.

Для наблюдения используются состояния:

```text
alive
suspect
dead
unknown
```

Также сохраняются история наблюдений и оценка стабильности.

Это диагностический слой.

**Ошибка HTTPS/TLS сама по себе не удаляет hostname из DNS-списка.**

DNS и доступность сервиса намеренно разделены.

Hostname может иметь полностью рабочий DNS, но:

- не принимать HTTPS на корневом пути;
- использовать другой протокол;
- ограничивать подключения;
- временно не отвечать;
- по-разному вести себя из разных сетей.

Поэтому HTTPS/TLS observation не является источником решения об удалении Exact DNS hostname.

## State и отчёты

Движок сохраняет состояние между запусками, поэтому решения принимаются не по одной проверке, а с учётом истории.

Для коллекции внутри её `data_dir` могут использоваться:

```text
state.json
discovery_state.json

pending.txt
suspect.txt
quarantine.txt
expired.txt
excluded.txt

runtime_candidate_state.json

service_state.json
service_alive.txt
service_suspect.txt
service_dead.txt
service_unknown.txt

report.md
```

### `state.json`

Основное состояние Exact DNS lifecycle.

Содержит hostname, их DNS state, результаты resolver'ов, публичные IPv4 и данные, необходимые для переходов между lifecycle states.

### `discovery_state.json`

Хранит прогресс автоматического discovery.

Это позволяет продолжать Certificate Transparency discovery между запусками, а не начинать его каждый раз заново.

### `pending.txt`

Hostname, которые ещё не получили достаточного подтверждения для публикации.

### `suspect.txt`

Опубликованные hostname, находящиеся в периоде подтверждённой DNS-деградации.

### `quarantine.txt`

Hostname, временно исключённые из публичного DNS-файла из-за DNS safety/lifecycle.

### `expired.txt`

Hostname, прошедшие длительный отрицательный lifecycle и выведенные из текущей проверки до повторного discovery.

### `excluded.txt`

Hostname, исключённые Hostname Policy.

Это семантическое состояние, а не DNS quarantine.

### `runtime_candidate_state.json`

Независимое состояние Runtime Candidate Intake.

Оно хранит Runtime Candidate наблюдения и не используется как источник Exact DNS-кандидатов.

### `service_state.json`

Отдельная история HTTPS/TLS observation.

Она не управляет Exact DNS lifecycle.

### `report.md`

Короткая сводка текущего состояния коллекции:

- DNS lifecycle;
- semantic exclusions;
- HTTPS/TLS observation;
- discovery status;
- основные диагностические показатели.

## Публичный DNS-файл

Каждая коллекция задаёт собственный `active_file`, например:

```text
Netflix_DNS
YouTube_DNS
Telegram_DNS
```

В публичный Exact DNS-файл попадают только hostname, которые прошли соответствующий DNS lifecycle и остаются допустимыми после Hostname Policy.

Runtime Candidate Feed сам по себе содержимое `*_DNS` не изменяет.

## Конфигурация

Стандартное имя конфигурационного файла caller-репозитория:

```text
dns-maintenance-v1.json
```

Минимальная структура:

```json
{
  "version": 1,
  "collections": [
    {
      "name": "example",
      "active_file": "Example_DNS",
      "data_dir": "dns/example"
    }
  ]
}
```

Дополнительные возможности подключаются конфигурацией коллекции:

```text
discovery
hostname_policy
runtime_candidate
```

DNS и HTTPS/TLS defaults также могут задаваться централизованно в секции:

```text
defaults
```

## GitHub Actions

Центральный репозиторий предоставляет reusable workflow:

```text
.github/workflows/reusable-maintenance.yml
```

Caller-репозиторий передаёт:

- путь к config;
- имя коллекции;
- режим dry-run;
- ref центрального engine.

Для production рекомендуется использовать конкретный проверенный commit SHA центрального engine вместо плавающего `main`.

Это позволяет точно понимать, какая версия движка обслуживает конкретный сервис, и не превращать очередной cron в эксперимент по непрерывной интеграции на живых данных.

## Основные принципы безопасности

Архитектура строится вокруг нескольких простых правил:

- один временный DNS-сбой не удаляет hostname;
- `TRANSIENT` не является отрицательным DNS-доказательством;
- публикуются только публичные IPv4;
- HTTPS/TLS failure не удаляет Exact DNS hostname;
- semantic exclusion отделён от DNS quarantine;
- Runtime Candidate observation не является DNS authority;
- Runtime Candidate не передаётся в Exact DNS candidate sources;
- отсутствующий или повреждённый Runtime Candidate Feed не уничтожает старое состояние;
- dry-run не записывает managed state;
- production workflow лучше привязывать к конкретному протестированному engine SHA.

Цель системы не в том, чтобы как можно быстрее удалить подозрительную запись.

Цель — поддерживать сетевые списки актуальными, не превращая временные сбои и внешние наблюдения в автоматические необратимые решения.
