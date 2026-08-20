# DNS-Maintenance

Universal maintenance engine for DNS hostname lists used by DKHNV service repositories.

## Status

**v1.0.0-rc1 / pilot.** Do not replace the working Telegram workflow yet. The current Telegram engine should keep collecting production history while this repository is tested independently.

## What v1 changes

The original Telegram pilot used counters such as `3 failed runs -> suspect` and `7 failed runs -> quarantine/dead`. That makes state semantics depend on workflow frequency. v1 replaces escalation with elapsed time plus a minimum amount of evidence.

Default DNS lifecycle:

- `suspect`: at least 72 hours of a maintained negative window and at least 3 confirmed negative observations;
- `quarantine`: at least 168 hours and at least 7 confirmed negative observations;
- `expired`: 720 hours (30 days) in quarantine;
- transient DNS errors do not advance lifecycle;
- a gap longer than 48 hours between negative observations starts a fresh negative timing window.

Default HTTPS/TLS observation:

- `suspect`: at least 72 hours and at least 3 failure observations;
- `dead`: at least 168 hours and at least 7 failure observations;
- `SKIPPED` does not advance failure state;
- HTTPS/TLS state never removes a hostname from the public DNS list;
- history is kept by calendar age (14 days), not by number of workflow runs.

This means the same lifecycle still means the same thing whether the caller runs once or four times per day.

## Repository model

The engine lives here. Service repositories keep only data and a tiny caller workflow.

Example service repository after migration:

```text
Telegram/
├── Telegram_DNS
├── dns-maintenance.json
├── dns/
│   └── telegram/
│       ├── manual.txt
│       ├── discovered.txt
│       ├── state.json
│       ├── discovery_state.json
│       ├── service_state.json
│       └── report.md
└── .github/workflows/
    └── dns-maintenance.yml
```

The reusable workflow checks out the caller repository and then checks out this engine separately. Generated files remain in the caller repository.

## Configuration

See `examples/telegram/dns-maintenance.json`.

A collection only needs:

```json
{
  "name": "telegram",
  "active_file": "Telegram_DNS",
  "data_dir": "dns/telegram"
}
```

Standard state/list paths are derived from `data_dir`; no Python code contains Telegram-specific paths.

## Local tests

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

## Pilot plan

1. Keep the existing Telegram workflow unchanged.
2. Create this repository and let CI pass.
3. Run v1 against a copied Telegram fixture locally/in a separate test repository.
4. After several days of production Telegram history, perform a v1 dry-run on the real Telegram repository.
5. Compare active DNS, DNS states and HTTPS/TLS states.
6. Only then migrate Telegram and enable four runs per day.
7. Tag the accepted engine as `v1.0.0` and pin service repositories to that tag.
