# AF-07 Operator Runbook

Status: `TEMPLATE / NOT INSTALLED`. Registration, start, stop, or removal of a Windows scheduled task requires a separate Human Authority gate.

## Safety and prerequisites

AF-07 uses the separate `python -m src.autonomy.service` lifecycle and does not modify `main.py`, control monitored projects, or activate providers. Python 3.12 and an exact reviewed repository revision are required. `REAL_PROJECT_MUTATION_ENABLED`, `CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES`, project write/restart/execute, strategy, and real-money flags remain false. G10 remains disabled and unauthorized.

Create an existing external runtime directory outside and not above any repository, plus an existing UTF-8 JSONL queue. The strict JSON config contains exactly: `schema_version`, `service_id`, `runtime_root`, `queue_path`, `repository_roots`, `supported_targets`, `cadence_seconds`, `backoff_initial_seconds`, `backoff_max_seconds`, `backoff_multiplier`, `max_consecutive_transient_failures`, and `health_stale_seconds`. Paths are absolute; symlink/reparse paths, unknown targets, unknown keys, and secret/token/password/API-key fields are blocked.

## Start, status, and graceful stop

Run a bounded foreground validation:

`python -m src.autonomy.service --config <ABSOLUTE_CONFIG> --cycles 3`

Inspect without service ownership or state mutation:

`python -m src.autonomy.service --config <ABSOLUTE_CONFIG> --status`

Ctrl+C requests graceful self-stop: STOPPING then STOPPED, SQLite close, and OS-lock release. Operational DB, lock, and owner metadata live only under `runtime_root`; committed `state/**` never represents service liveness.

## Restart and crash recovery

Restart with the same config/runtime root. The first canonical `AutonomyRuntime.run_once()` performs integrity verification, ingestion, stale lease/session reconciliation, APPLYING grant recovery, and routing. Verify monotonic cycle count, preserved tasks/provenance/retry state, no duplicate lease/result/replay, and no automatic completion. A stale active heartbeat is `CRASH_SUSPECTED`, not fabricated CRASHED.

Never delete a lock merely because metadata looks stale. Attempt the OS lock; file/PID metadata alone is not ownership. `INTEGRITY_BLOCKED` and `BLOCKED` require human diagnosis and have no automatic retry. Only allowlisted timeout or SQLite busy/locked failures enter bounded BACKOFF. Provider absence remains NOT_CONNECTED/UNAVAILABLE.

## Windows preparation and rollback

`ops/af07-task-template.xml` is a non-installed template with placeholders for Python, repository root, and config. Registration/start/stop, credentials, elevation, and startup persistence require separate Human Authority. No scheduler command is run here.

For later-authorized rollback, stop only the AF-07 instance, inspect status, unregister only the exact task, and preserve the runtime DB for audit. Do not delete locks blindly, modify protected evidence, or touch monitored projects. Runtime DB and lifecycle metadata remain under the configured external runtime root; never place secrets there.
