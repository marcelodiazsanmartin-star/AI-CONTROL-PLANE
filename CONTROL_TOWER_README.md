# AI CONTROL TOWER — Phase 0

## Purpose

AI CONTROL TOWER is a private local operations visualizer for issue #16. It shows
deterministic project, gate, evidence, agent, task, alert, approval, and runtime
data without becoming a source of truth. Phase 0 is strictly read-only.

## Architecture

```text
Browser http://127.0.0.1:3000
             ↓ GET with restricted CORS
Static CONTROL TOWER frontend
             ↓
http://127.0.0.1:8000/api/v1/dashboard
             ↓
Loopback-only Python read-only API
             ↓
Canonical contract + fail-closed calculations
             ↓
Deterministic fixtures (not production telemetry)
```

The frontend and API are disposable projections. Turning off the local PC removes
only the dashboard. Future canonical runtime truth must remain cloud-independent
and outside this viewer.

## Setup

Python 3.12 is required. The application has no third-party runtime dependencies.
`pytest` is needed only for tests.

```powershell
python --version
python -m pip install pytest
```

## Start on Windows PowerShell

From the repository root, start the backend in terminal 1:

```powershell
python -m control_tower.api
```

The backend always binds to `127.0.0.1`; there is no host override and it cannot
be configured to listen on `0.0.0.0`.

Start the frontend in terminal 2 using this exact loopback-only command:

```powershell
python -m http.server 3000 --bind 127.0.0.1 --directory control_tower/frontend
```

Open:

- Dashboard: `http://127.0.0.1:3000`
- Application health: `http://127.0.0.1:8000/health`
- Canonical dashboard API: `http://127.0.0.1:8000/api/v1/dashboard`

`/health` reports only CONTROL TOWER application health. It explicitly does not
report the health of AI-CONTROL-PLANE, ORACLE-AI, MICRO-MARKET-ORACLE, or an
autonomous system.

## Security model and read-only guarantee

Phase 0 fixes the policy to:

```text
READ_ONLY = TRUE
LIVE_MONEY_CONTROLS = FALSE
APPROVAL_EXECUTION = FALSE
STRATEGY_MUTATION = FALSE
RISK_MUTATION = FALSE
CREDENTIAL_MUTATION = FALSE
```

Only these reads are supported:

```text
GET /health
GET /api/v1/dashboard
```

`POST`, `PUT`, `PATCH`, and `DELETE` return HTTP 405 with
`READ_ONLY_PHASE_0` on valid and invalid routes. Request handlers do not read or
write repository files. Tests hash `state/**`, `reports/**`, and
`directives/audit/**` before and after live API traffic.

CORS is limited to `http://localhost:3000` and
`http://127.0.0.1:3000`. External origins receive no
`Access-Control-Allow-Origin` header; wildcard CORS is not used. The frontend
uses CSP and renders API values through `textContent` and DOM element creation.
It does not use `innerHTML` for API, adapter, alert, agent, task, evidence, or
future telemetry values.

There are no APPROVE, REJECT, EXECUTE, LIVE, CHANGE RISK, or other mutation
controls.

## Canonical data model

`control_tower/models.py` defines PROJECT, MILESTONE, TASK, AGENT, GATE,
EVIDENCE, ALERT, APPROVAL, RUNTIME, and COST. Runtime states are `HEALTHY`,
`WORKING`, `DEGRADED`, `STALE`, `OFFLINE`, `UNKNOWN`, and `BLOCKED`. Alert levels
are `INFO`, `WARNING`, `ACTION_REQUIRED`, `HUMAN_APPROVAL`, `CRITICAL`, and
`ORACLE`.

Agent records expose availability, current task, task stage, progress, heartbeat,
provider status, quota status, and blocker. Missing quota and provider data remain
`UNKNOWN`.

## Fixture mode

The Phase 0 response carries `data_mode: DETERMINISTIC_FIXTURE` and
`dashboard_is_source_of_truth: false`. The UI displays `DATA MODE:
DETERMINISTIC_FIXTURE` in a prominent banner. ORACLE and MICRO fields without a
verified source remain `UNKNOWN` or `NOT_CONNECTED`; they are never replaced by
plausible-looking telemetry.

## Runtime truth rules

Persisted state is not runtime proof. Resolution is fail-closed:

- Missing, malformed, or timezone-naive heartbeat → `UNKNOWN`.
- Future heartbeat beyond tolerated clock skew → `UNKNOWN`.
- Expired heartbeat → `STALE`, never `WORKING`.
- Persisted `RUNNING` without a fresh observation → `UNKNOWN`.
- Conflicting persisted and observed states → `BLOCKED`.
- Explicit blocker → `BLOCKED`.

## Weighted progress rules

Each project keeps three independent dimensions: plan progress, certification
readiness, and operational readiness. There is no combined synthetic percentage.

- Plan progress is the weighted average of explicit milestone progress.
- Certification and operational readiness count only weighted gates whose
  effective state is `PASS`.
- `PASS` without complete referenced evidence becomes effective `UNKNOWN`.
- Missing milestones, zero/negative/malformed weights, and malformed progress
  fail closed to `UNKNOWN` (`null` in JSON).
- Unknown or blocked gates earn zero readiness weight.
- No percentage is estimated by an LLM.

## Tests

Focused CONTROL TOWER suite:

```powershell
python -m pytest tests/test_control_tower.py -q
```

Complete repository suite must be run in a disposable copy, never against this
authorized worktree, because legacy tests may exercise mutable runtime/state paths:

```powershell
python -m pytest tests/ -q
```

Current release-candidate verification results are recorded in the implementation
review report, not injected into the dashboard as live evidence.

## Phase 0 limitations and future integration

- Data is deterministic fixture data, not live telemetry.
- ORACLE and MICRO adapters are not connected.
- No cloud runtime, quota, cost, market, signal, position, P&L, drawdown, slippage,
  discovery, or scheduler source is queried.
- Approvals are display-only.
- Phase 1 may add deterministic read-only adapters to canonical sources, but must
  preserve source labels, freshness checks, fail-closed semantics, loopback
  defaults, and the separation between dashboard and source of truth.

## Troubleshooting

- If the UI says API offline, verify terminal 1 is running and open
  `http://127.0.0.1:8000/health`.
- Serve the frontend from `127.0.0.1:3000`; another origin is intentionally denied
  CORS access.
- If port 8000 or 3000 is occupied, stop the conflicting local process. The
  frontend API URL is intentionally fixed for Phase 0.
- Do not replace loopback binds with `0.0.0.0`.

## Files delivered

- `CONTROL_TOWER_README.md`
- `control_tower/__init__.py`
- `control_tower/api.py`
- `control_tower/calculations.py`
- `control_tower/fixtures.py`
- `control_tower/models.py`
- `control_tower/frontend/index.html`
- `control_tower/frontend/app.js`
- `control_tower/frontend/styles.css`
- `tests/test_control_tower.py`

No CONTROL-04, CONTROL-05, production, report, audit, directive, or canonical
state file is part of the CONTROL TOWER implementation.
