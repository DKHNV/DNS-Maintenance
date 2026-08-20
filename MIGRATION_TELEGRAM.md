# Telegram migration plan

Do **not** apply this file yet. It documents the later cut-over from the current embedded Telegram engine to the central engine.

## Compatibility

v1 accepts the state files already produced by the Telegram pilot:

- DNS `state.json` version 1 -> v2;
- discovery state version 1 -> v2;
- service state versions 1/2 -> v3.

Migration is intentionally conservative. Old count-based failures are not converted into invented elapsed-time windows. On the first v1 negative/failure observation, the new `negative_since` / `failure_since` timers start from that observation. Existing `suspect`, `quarantine` and `dead` labels are preserved until a successful recovery or later escalation.

## Planned cut-over

1. Add `dns-maintenance.json` to `DKHNV/Telegram` using `examples/telegram/dns-maintenance.json`.
2. Add a temporary manual-only caller workflow based on `caller-workflow-pilot.yml`.
3. Run it with `dry_run=true` and compare output with the current engine.
4. Make a backup tag/commit of the Telegram repository.
5. Run v1 once in write mode and inspect the state-format migration diff.
6. Replace the embedded workflow with the production caller workflow.
7. Remove the old local `dns_maintenance/` code only after several successful central-engine runs.
8. Tag central engine `v1.0.0`, pin Telegram to it, then change schedule to 4 runs/day.
