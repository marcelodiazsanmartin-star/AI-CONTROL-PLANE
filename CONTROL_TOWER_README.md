# AI CONTROL TOWER — Operational Runbook & System Specification

## 1. Purpose & Authority Boundaries

AI CONTROL TOWER is the local operational visualizer and monitoring plane for the AI-CONTROL-PLANE system (issues #16, #17, #21).

### Core Invariants & Separation of Duties
- **Strictly Read-Only**: The control tower has zero authority to mutate state, approve directives, alter risk limits, or execute live transactions.
- **Disposable Projection**: The dashboard and its servers are ephemeral visualization projections. Persisted repository truth remains independent and immutable.
- **Fail-Closed Truth Binding**: If an upstream source is missing, stale, conflicting, unauthenticated, or malformed, the visualizer displays `UNKNOWN`, `DEGRADED`, or `BLOCKED`. No plausible-looking data or synthetic green status is ever fabricated.

---

## 2. Architecture & Service Model (CT-03 / CT-04)

```text
Browser http://127.0.0.1:3000
             ↓ GET (Restricted CORS: origin http://127.0.0.1:3000 only)
Static Frontend Server (Port 3000, Loopback Only, Strict CSP)
             ↓ Fetch /api/v1/dashboard
Backend Control Tower Server (Port 8000, Loopback Only, Read-Only)
             ↓
Resilient Adapter Executor (Timeouts, Circuit Breakers, Bounded Admission, Generation Safety)
             ↓
[Control Plane State]  [ORACLE-AI Shadow]  [Micro-Market Shadow]  [Directive Channel]
      (state/**)             (state/**)             (state/**)        (directives/**)
```

Both backend and frontend run under a unified service supervisor managed via `python -m control_tower`.

---

## 3. Quick Start & Operational Commands

### Prerequisites
- Python 3.12+
- Local loopback network access (`127.0.0.1`)

### Starting the Service (Unified Dual-Server Supervisor)
From the repository root:
```powershell
python -m control_tower
```
This single command:
1. Validates loopback port availability (ports 8000 and 3000).
2. Spawns the Backend API Server (`127.0.0.1:8000`).
3. Spawns the Frontend Asset Server (`127.0.0.1:3000`).
4. Collects adapters on demand when `/ready` or `/api/v1/dashboard` is requested.
5. Supervises background server threads in-process.
6. Handles graceful shutdown on `Ctrl+C` (SIGINT / SIGTERM).

---

## 4. Endpoint Specification

| Endpoint | Method | Purpose | Response Format / Contract |
| :--- | :--- | :--- | :--- |
| `/health` | `GET` | Application liveness probe | JSON `{"status": "HEALTHY", "service": "CONTROL_TOWER", ...}` |
| `/ready` | `GET` | Tower projection readiness; confirms a dashboard can be built, not that upstreams are healthy | HTTP 200 `READY/PASS`, or HTTP 503 `NOT_READY/FAIL` when projection building raises an error |
| `/api/v1/dashboard` | `GET` | Canonical operations projection | JSON compliant with Dashboard Schema v3 |
| All routes | `POST, PUT, PATCH, DELETE` | Forbidden mutation attempt | HTTP 405 Method Not Allowed with JSON `{"error": "READ_ONLY: ..."}` |
| Frontend Assets | `GET` | UI HTML, JS, CSS | Served on port 3000 with strict CSP & security headers |

---

## 5. Security & Network Model

1. **Loopback Binding Enforcement**:
   - Backend (`create_server`) and frontend (`create_frontend_server`) accept only the numeric bind address `127.0.0.1`.
   - Hostname aliases, IPv6, `0.0.0.0`, and external addresses fail closed with `ValueError`; the bind boundary does not depend on DNS or hosts-file resolution.
2. **Restricted CORS**:
   - `Access-Control-Allow-Origin` is granted exclusively to `http://127.0.0.1:3000` and `http://localhost:3000`.
   - Wildcard CORS (`*`) and external origins are strictly forbidden.
3. **Safe DOM Rendering & CSP**:
   - Frontend renders data strictly through `textContent` and DOM nodes; `innerHTML`, `outerHTML`, `eval()`, and `document.write` are prohibited.
   - Strict Content Security Policy (`default-src 'self'`, `connect-src http://127.0.0.1:8000`, `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`).

---

## 6. Adapters, Freshness SLAs & Resilience Mechanics

### Verified Read-Only Adapters
- `control-plane-state` (`state/control_plane.json` / `global_status.json`, SLA: 3600s)
- `oracle-ai-state` (`state/oracle.json`, SLA: 3600s)
- `micro-market-oracle-state` (`state/micro_market_oracle.json`, SLA: 3600s)
- `directive-channel` (`directives/inbound/`, `state/execution_queue.json`, SLA: 60s)

### Resilience Architecture (`ResilientAdapterExecutor`)
- **Timeout Isolation**: Adapters execute in bounded worker threads with strict per-attempt timeouts.
- **Circuit Breakers**: Consecutive failures trip the per-adapter circuit to `OPEN`, preventing slow downstreams from starving the system.
- **Bounded Admission Control**:
  - Admission capacity is strictly bounded by a persistent `threading.BoundedSemaphore(max_workers + max_queue_depth)`.
  - When all worker threads and queue slots are saturated (e.g. by permanently hanging adapters), new tasks are rejected immediately (< 1ms) with `CAPACITY_EXHAUSTED` and `truth_status=SourceStatus.UNKNOWN`.
- **Release-Once Lease Ownership**:
  - Permits are owned by the executing worker thread and released strictly in a `finally` block upon completion.
  - Failures during submit release the permit immediately; cancellations of unstarted queued futures release permits via callback. Late callbacks cannot over-release or inflate capacity.
- **Generation Safety & Clean Restart**:
  - `shutdown(wait=False)` safely cancels queued futures and preserves persistent capacity bounds without permit leaks across restarts.

---

## 7. Operational Runbook & Smoke Test Verification

### Step-by-Step Smoke Test Procedure

1. **Start the service**:
   ```powershell
   python -m control_tower
   ```

2. **Verify application health**:
   ```powershell
   curl -i http://127.0.0.1:8000/health
   ```
   *Expected Output*: HTTP 200 with `status: "HEALTHY"`.

3. **Verify readiness**:
   ```powershell
   curl -i http://127.0.0.1:8000/ready
   ```
   *Expected Output*: HTTP 200 with `status: "READY"` and `readiness: "PASS"`. This does not assert upstream connectivity or autonomous-system readiness; inspect `/api/v1/dashboard` source truth for those conditions.

4. **Verify canonical dashboard payload**:
   ```powershell
   curl -i http://127.0.0.1:8000/api/v1/dashboard
   ```
   *Expected Output*: HTTP 200 with valid schema, project readiness dimensions, and sources.

5. **Verify read-only mutation rejection**:
   ```powershell
   curl -i -X POST http://127.0.0.1:8000/api/v1/dashboard
   ```
   *Expected Output*: HTTP 405 Method Not Allowed with body containing `READ_ONLY`.

6. **Verify frontend asset serving**:
   ```powershell
   curl -i http://127.0.0.1:3000
   ```
   *Expected Output*: HTTP 200 with HTML and security headers.

---

## 8. Disaster Recovery & Troubleshooting

| Symptom | Cause | Remediation |
| :--- | :--- | :--- |
| `Port 8000 / 3000 occupied` | Prior instance or conflicting local process running | Identify conflicting process (e.g. `Get-Process` on Windows or `lsof`/`netstat`) and terminate conflicting process. |
| `API OFFLINE` in UI | Backend server stopped or port blocked | Verify `python -m control_tower` is running and `http://127.0.0.1:8000/health` responds. |
| `DATA MODE: DEGRADED` | Upstream state file missing or stale | Check adapter health panel in UI or query `/api/v1/dashboard` sources for the specific adapter `error_code`. |
| `CAPACITY_EXHAUSTED` | Adapter execution hang or severe slowdown | Circuit breaker and backpressure will isolate the failing adapter. Restarting the service via `python -m control_tower` safely resets thread workers. |

---

## 9. Current Operational Scope & Limitations

- **Observability Only**: Visualizes status; does not execute directives or orchestrate systems.
- **Independent Verification Required**: Evidence and gate statuses reflect verified verification results (`verification_result == "PASS"`) and code identities; unverified claims fail closed.
- **Single Host Operation**: Designed strictly for private local loopback operation. The service does not implement client authentication; its boundaries are loopback binding, Host validation, restricted CORS, read-only handlers, and browser CSP.
