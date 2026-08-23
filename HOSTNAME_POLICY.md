# Hostname Policy v1

This package adds an opt-in semantic filtering layer to DNS-Maintenance.

## Behavior

The existing pipeline remains unchanged when `hostname_policy` is absent or disabled.

When enabled, policy is applied after DNS validation and before HTTPS/TLS probing:

CertSpotter -> DNS validation -> Hostname Policy -> HTTPS/TLS -> report

Semantic exclusions use a separate `excluded` state and `excluded.txt`.
They are NOT DNS quarantine and do not weaken Public IPv4 Guard.

## Rule format

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

Supported match types in v1:

- `exact`: exact hostname.
- `suffix`: the suffix itself or any subdomain below it.

Precedence:

1. DNS safety states (`quarantine`, `expired`) always win.
2. Persistent manual source override wins semantic policy, but still requires a fresh DNS OK before republishing.
3. `allow` rules win over broader `exclude` rules.
4. unmatched names are allowed.

## Rollout safety

Do not enable `hostname_policy` in service repositories immediately after installing this package.
First run central tests. Then use Grok as the first pilot with a dry-run.
