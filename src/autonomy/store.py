"""Transactional local task, worker and lease truth for AF-00."""
from __future__ import annotations
import hashlib, json, math, re, sqlite3, time, uuid
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION=1; MAX_RETRY=1_000_000
TERMINAL={"COMPLETED","FAILED_SAFE","DEAD_LETTER"}; LEASEABLE={"QUEUED","WAITING_CAPACITY","RETRYING"}
class BlockedError(RuntimeError): pass
class IntegrityBlockedError(BlockedError): pass
class TaskState(str,Enum):
 NEW="NEW"; VALIDATED="VALIDATED"; QUEUED="QUEUED"; ASSIGNED="ASSIGNED"; LEASED="LEASED"; RUNNING="RUNNING"; EVIDENCE_PENDING="EVIDENCE_PENDING"; REVIEW_PENDING="REVIEW_PENDING"; WAITING_HUMAN="WAITING_HUMAN"; COMPLETED="COMPLETED"; WAITING_CAPACITY="WAITING_CAPACITY"; RETRYING="RETRYING"; FAILED_SAFE="FAILED_SAFE"; DEAD_LETTER="DEAD_LETTER"
VALID_STATES={x.value for x in TaskState}
def clean(v:Any)->str:
 s=str(v or "")[:512]; s=re.sub(r"(?i)(token|secret|password|authorization)\s*[:=]\s*\S+",r"\1=[REDACTED]",s)
 return "".join(c for c in s if c >= " " and c not in "<>\x7f")
def packed(v:Iterable[str])->str: return json.dumps(sorted({clean(x) for x in v if clean(x)}),separators=(",",":"))

class AutonomyStore:
 """SQLite state machine. Intentionally exposes no subprocess/repository/provider API."""
 def __init__(self,path:Path|str,*,busy_timeout_ms:int=500):
  self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True)
  try:
   self.db=sqlite3.connect(self.path,timeout=max(1,busy_timeout_ms)/1000,isolation_level=None,check_same_thread=False)
   self.db.row_factory=sqlite3.Row; self.db.execute("PRAGMA foreign_keys=ON"); self.db.execute(f"PRAGMA busy_timeout={max(1,busy_timeout_ms)}")
   self._init()
  except (sqlite3.DatabaseError,OSError) as e: raise IntegrityBlockedError("store unavailable or corrupt") from e
 def close(self): self.db.close()
 def _init(self):
  try:
   exists=self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_meta'").fetchone()
   if exists:
    row=self.db.execute("SELECT version FROM schema_meta").fetchone()
    if not row or row[0]!=SCHEMA_VERSION: raise IntegrityBlockedError("unsupported schema")
    if self.db.execute("PRAGMA quick_check").fetchone()[0]!="ok": raise IntegrityBlockedError("integrity failure")
    return
   self.db.executescript("""BEGIN IMMEDIATE;
CREATE TABLE schema_meta(version INTEGER NOT NULL); INSERT INTO schema_meta VALUES(1);
CREATE TABLE workers(worker_id TEXT PRIMARY KEY,kind TEXT NOT NULL,capabilities TEXT NOT NULL,targets TEXT NOT NULL,registered_at REAL NOT NULL,last_heartbeat REAL NOT NULL,heartbeat_sla REAL NOT NULL CHECK(heartbeat_sla>0),capacity INTEGER NOT NULL CHECK(capacity>=0));
CREATE TABLE tasks(task_id TEXT PRIMARY KEY,directive_id TEXT UNIQUE,target_project TEXT NOT NULL,capability TEXT NOT NULL,state TEXT NOT NULL,priority INTEGER NOT NULL,created_at REAL NOT NULL,updated_at REAL NOT NULL,requires_human_approval INTEGER NOT NULL,governance_allowed INTEGER NOT NULL,attempt_count INTEGER NOT NULL DEFAULT 0,retry_budget INTEGER NOT NULL,assigned_worker_id TEXT REFERENCES workers(worker_id),lease_id TEXT UNIQUE,lease_expires_at REAL,last_worker_heartbeat REAL,evidence_status TEXT NOT NULL DEFAULT 'NONE',terminal_reason TEXT,error_code TEXT);
CREATE TABLE evidence(task_id TEXT NOT NULL REFERENCES tasks(task_id),evidence_id TEXT NOT NULL,sha256 TEXT NOT NULL,received_at REAL NOT NULL,PRIMARY KEY(task_id,evidence_id),UNIQUE(task_id,sha256));
CREATE TABLE audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,task_id TEXT,event TEXT NOT NULL,at REAL NOT NULL,details TEXT NOT NULL); COMMIT;""")
  except sqlite3.DatabaseError as e: raise IntegrityBlockedError("schema initialization failed") from e
 def now(self,n=None):
  v=time.time() if n is None else float(n)
  if not math.isfinite(v) or v<0: raise BlockedError("invalid clock")
  return v
 def audit(self,t,e,n,d=""): self.db.execute("INSERT INTO audit(task_id,event,at,details) VALUES(?,?,?,?)",(t,e,n,clean(d)))
 def task(self,task_id):
  r=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(clean(task_id),)).fetchone()
  if not r: raise BlockedError("unknown task")
  if r["state"] not in VALID_STATES: raise IntegrityBlockedError("unknown task state")
  return dict(r)
 def create_task(self,*,task_id,directive_id,target_project,capability,priority=0,requires_human_approval=False,governance_allowed=False,retry_budget=0,now=None):
  n=self.now(now)
  if isinstance(retry_budget,bool) or not isinstance(retry_budget,int) or not 0<=retry_budget<=MAX_RETRY: raise BlockedError("invalid retry budget")
  if directive_id:
   r=self.db.execute("SELECT * FROM tasks WHERE directive_id=?",(clean(directive_id),)).fetchone()
   if r:
    if (r["task_id"],r["target_project"],r["capability"])!=(clean(task_id),clean(target_project),clean(capability)): raise BlockedError("identity conflict")
    return dict(r)
  state="WAITING_HUMAN" if requires_human_approval else "QUEUED"
  try:
   self.db.execute("BEGIN IMMEDIATE"); self.db.execute("INSERT INTO tasks(task_id,directive_id,target_project,capability,state,priority,created_at,updated_at,requires_human_approval,governance_allowed,retry_budget) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(clean(task_id),clean(directive_id) or None,clean(target_project),clean(capability),state,int(priority),n,n,int(requires_human_approval),int(governance_allowed),retry_budget)); self.audit(task_id,"CREATED",n,state); self.db.execute("COMMIT")
  except sqlite3.IntegrityError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("duplicate task") from e
  return self.task(task_id)
 def register_worker(self,*,worker_id,kind,capabilities,targets,heartbeat_sla,capacity,now=None):
  n=self.now(now)
  if heartbeat_sla<=0 or capacity<0: raise BlockedError("invalid worker")
  self.db.execute("INSERT INTO workers VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(worker_id) DO UPDATE SET kind=excluded.kind,capabilities=excluded.capabilities,targets=excluded.targets,last_heartbeat=excluded.last_heartbeat,heartbeat_sla=excluded.heartbeat_sla,capacity=excluded.capacity",(clean(worker_id),clean(kind),packed(capabilities),packed(targets),n,n,float(heartbeat_sla),int(capacity)))
 def heartbeat(self,worker_id,*,now=None,observed_at=None):
  n=self.now(now); o=n if observed_at is None else self.now(observed_at)
  if o>n+1: raise BlockedError("future heartbeat")
  if self.db.execute("UPDATE workers SET last_heartbeat=? WHERE worker_id=?",(o,clean(worker_id))).rowcount!=1: raise BlockedError("unknown worker")
 def heartbeat_with_capacity(self,worker_id,*,capacity,now=None,observed_at=None):
  """Atomically publish heartbeat freshness and its associated capacity."""
  n=self.now(now);o=n if observed_at is None else self.now(observed_at)
  if o>n+1 or isinstance(capacity,bool) or not isinstance(capacity,int) or capacity<0:raise BlockedError("invalid heartbeat")
  try:
   self.db.execute("BEGIN IMMEDIATE")
   changed=self.db.execute("UPDATE workers SET last_heartbeat=?,capacity=? WHERE worker_id=?",(o,capacity,clean(worker_id))).rowcount
   if changed!=1:raise BlockedError("unknown worker")
   self.db.execute("COMMIT")
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
  except sqlite3.OperationalError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("store busy") from e
  except sqlite3.DatabaseError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def worker_status(self,worker_id,*,now=None):
  n=self.now(now); r=self.db.execute("SELECT * FROM workers WHERE worker_id=?",(clean(worker_id),)).fetchone()
  if not r: raise BlockedError("unknown worker")
  active=self.db.execute("SELECT count(*) FROM tasks WHERE assigned_worker_id=? AND state IN('LEASED','RUNNING') AND lease_expires_at>?",(worker_id,n)).fetchone()[0]
  return {**dict(r),"status":"AVAILABLE" if r["last_heartbeat"]<=n+1 and n-r["last_heartbeat"]<=r["heartbeat_sla"] else "STALE","active_lease_count":active}
 def claim(self,task_id,worker_id,*,lease_seconds=30,now=None):
  n=self.now(now)
  if isinstance(lease_seconds,bool) or not isinstance(lease_seconds,(int,float)) or not math.isfinite(float(lease_seconds)) or lease_seconds<=0:raise BlockedError("invalid lease duration")
  try:
   self.db.execute("BEGIN IMMEDIATE"); t=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone(); w=self.db.execute("SELECT * FROM workers WHERE worker_id=?",(worker_id,)).fetchone()
   if not t or not w or t["state"] not in LEASEABLE or t["requires_human_approval"] or not t["governance_allowed"]: raise BlockedError("not leaseable")
   if n-w["last_heartbeat"]>w["heartbeat_sla"] or w["last_heartbeat"]>n+1: raise BlockedError("stale worker")
   if t["capability"] not in json.loads(w["capabilities"]) or t["target_project"] not in json.loads(w["targets"]): raise BlockedError("incompatible worker")
   active=self.db.execute("SELECT count(*) FROM tasks WHERE assigned_worker_id=? AND state IN('LEASED','RUNNING') AND lease_expires_at>?",(worker_id,n)).fetchone()[0]
   if active>=w["capacity"]: raise BlockedError("capacity exhausted")
   lid=uuid.uuid4().hex; exp=n+lease_seconds
   if self.db.execute("UPDATE tasks SET state='LEASED',assigned_worker_id=?,lease_id=?,lease_expires_at=?,last_worker_heartbeat=?,updated_at=? WHERE task_id=? AND state IN('QUEUED','WAITING_CAPACITY','RETRYING')",(worker_id,lid,exp,w["last_heartbeat"],n,task_id)).rowcount!=1: raise BlockedError("claim lost")
   self.audit(task_id,"LEASED",n,worker_id); self.db.execute("COMMIT"); return {"task_id":task_id,"worker_id":worker_id,"lease_id":lid,"expires_at":exp}
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
  except sqlite3.OperationalError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("store busy") from e
 def renew(self,task_id,worker_id,lease_id,*,lease_seconds=30,now=None):
  n=self.now(now); exp=n+lease_seconds
  try:
   self.db.execute("BEGIN IMMEDIATE")
   changed=self.db.execute("UPDATE tasks SET lease_expires_at=?,updated_at=? WHERE task_id=? AND assigned_worker_id=? AND lease_id=? AND state IN('LEASED','RUNNING') AND lease_expires_at>?",(exp,n,task_id,worker_id,lease_id,n)).rowcount
   if changed!=1:raise BlockedError("invalid lease owner")
   self.audit(task_id,"LEASE_RENEWED",n,worker_id);self.db.execute("COMMIT");return exp
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def start(self,task_id,worker_id,lease_id,*,now=None):
  n=self.now(now)
  try:
   self.db.execute("BEGIN IMMEDIATE");w=self.db.execute("SELECT * FROM workers WHERE worker_id=?",(worker_id,)).fetchone()
   if not w or n-w["last_heartbeat"]>w["heartbeat_sla"] or w["last_heartbeat"]>n+1:raise BlockedError("cannot run")
   changed=self.db.execute("UPDATE tasks SET state='RUNNING',updated_at=? WHERE task_id=? AND state='LEASED' AND assigned_worker_id=? AND lease_id=? AND lease_expires_at>?",(n,task_id,worker_id,lease_id,n)).rowcount
   if changed!=1:raise BlockedError("cannot run")
   self.audit(task_id,"RUNNING",n,worker_id);self.db.execute("COMMIT")
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def reclaim_expired(self,task_id,*,now=None):
  n=self.now(now)
  try:
   self.db.execute("BEGIN IMMEDIATE");t=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone()
   if not t or t["state"] not in {"LEASED","RUNNING"} or t["lease_expires_at"]>n:raise BlockedError("not reclaimable")
   a=t["attempt_count"]+1;state="DEAD_LETTER" if a>t["retry_budget"] else "RETRYING"
   changed=self.db.execute("UPDATE tasks SET state=?,attempt_count=?,assigned_worker_id=NULL,lease_id=NULL,lease_expires_at=NULL,updated_at=? WHERE task_id=? AND state IN('LEASED','RUNNING') AND lease_expires_at<=?",(state,a,n,task_id,n)).rowcount
   if changed!=1:raise BlockedError("reclaim lost")
   self.audit(task_id,"LEASE_EXPIRED",n,state);self.db.execute("COMMIT")
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def reconcile_stale_workers(self,*,now=None):
  """Fail running work back to retry/dead-letter when owner truth is stale."""
  n=self.now(now); changed=[]
  rows=self.db.execute("""SELECT t.task_id FROM tasks t JOIN workers w ON w.worker_id=t.assigned_worker_id
WHERE t.state='RUNNING' AND (? - w.last_heartbeat > w.heartbeat_sla OR w.last_heartbeat > ? + 1) ORDER BY t.task_id""",(n,n)).fetchall()
  for row in rows:
   t=self.task(row[0]); a=t["attempt_count"]+1; state="DEAD_LETTER" if a>t["retry_budget"] else "RETRYING"
   self.db.execute("UPDATE tasks SET state=?,attempt_count=?,assigned_worker_id=NULL,lease_id=NULL,lease_expires_at=NULL,error_code='STALE_WORKER',updated_at=? WHERE task_id=?",(state,a,n,row[0])); self.audit(row[0],"STALE_WORKER_RECONCILED",n,state); changed.append(row[0])
  return changed
 def fail_attempt(self,task_id,worker_id,lease_id,*,reason,error_code="WORKER_FAILURE",now=None):
  n=self.now(now); t=self.task(task_id)
  if t["state"] not in {"LEASED","RUNNING"} or t["assigned_worker_id"]!=worker_id or t["lease_id"]!=lease_id: raise BlockedError("invalid reporter")
  a=t["attempt_count"]+1; state="DEAD_LETTER" if a>t["retry_budget"] else "RETRYING"
  self.db.execute("UPDATE tasks SET state=?,attempt_count=?,assigned_worker_id=NULL,lease_id=NULL,lease_expires_at=NULL,terminal_reason=?,error_code=?,updated_at=? WHERE task_id=?",(state,a,clean(reason),clean(error_code),n,task_id)); self.audit(task_id,"ATTEMPT_FAILED",n,state)
 def submit_result(self,task_id,worker_id,lease_id,*,evidence_id,sha256,now=None):
  n=self.now(now)
  try:
   self.db.execute("BEGIN IMMEDIATE");t=self.db.execute("SELECT * FROM tasks WHERE task_id=?",(task_id,)).fetchone();w=self.db.execute("SELECT * FROM workers WHERE worker_id=?",(worker_id,)).fetchone()
   if not t or not w or t["state"] not in {"LEASED","RUNNING","EVIDENCE_PENDING"} or t["assigned_worker_id"]!=worker_id or t["lease_id"]!=lease_id or t["lease_expires_at"]<=n or n-w["last_heartbeat"]>w["heartbeat_sla"] or w["last_heartbeat"]>n+1:raise BlockedError("invalid result owner")
   if not evidence_id or not sha256 or not re.fullmatch(r"[0-9a-fA-F]{64}",sha256):
    self.db.execute("UPDATE tasks SET state='EVIDENCE_PENDING',evidence_status='MISSING_OR_INVALID' WHERE task_id=?",(task_id,));self.db.execute("COMMIT");raise BlockedError("evidence required")
   self.db.execute("INSERT INTO evidence VALUES(?,?,?,?)",(task_id,clean(evidence_id),sha256.lower(),n));self.db.execute("UPDATE tasks SET state='REVIEW_PENDING',evidence_status='RECEIVED',updated_at=? WHERE task_id=?",(n,task_id));self.audit(task_id,"RESULT_RECEIVED",n,evidence_id);self.db.execute("COMMIT")
  except sqlite3.IntegrityError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("duplicate evidence") from e
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def complete_after_review(self,task_id,*,evidence_valid,now=None):
  n=self.now(now); t=self.task(task_id)
  if t["state"]!="REVIEW_PENDING" or t["evidence_status"]!="RECEIVED" or not evidence_valid: raise BlockedError("valid review required")
  self.db.execute("UPDATE tasks SET state='COMPLETED',evidence_status='VALID',assigned_worker_id=NULL,lease_id=NULL,lease_expires_at=NULL,updated_at=? WHERE task_id=?",(n,task_id)); self.audit(task_id,"COMPLETED_AFTER_REVIEW",n)
 def route_or_wait(self,task_id,*,now=None):
  n=self.now(now); t=self.task(task_id)
  if t["state"] in TERMINAL or t["state"]=="WAITING_HUMAN" or not t["governance_allowed"]: raise BlockedError("routing prohibited")
  for r in self.db.execute("SELECT worker_id FROM workers ORDER BY worker_id"):
   s=self.worker_status(r[0],now=n)
   if s["status"]=="AVAILABLE" and s["active_lease_count"]<s["capacity"] and t["capability"] in json.loads(s["capabilities"]) and t["target_project"] in json.loads(s["targets"]): return r[0]
  self.db.execute("UPDATE tasks SET state='WAITING_CAPACITY',updated_at=? WHERE task_id=?",(n,task_id)); self.audit(task_id,"WAITING_CAPACITY",n); return None
 def mark_waiting_capacity(self,task_id,*,now=None):
  """Record verified absence of capacity without introducing AF-02 states."""
  n=self.now(now)
  try:
   self.db.execute("BEGIN IMMEDIATE")
   changed=self.db.execute("UPDATE tasks SET state='WAITING_CAPACITY',updated_at=? WHERE task_id=? AND state IN('QUEUED','WAITING_CAPACITY','RETRYING') AND requires_human_approval=0 AND governance_allowed=1",(n,clean(task_id))).rowcount
   if changed!=1:raise BlockedError("task cannot wait for capacity")
   self.audit(task_id,"WAITING_CAPACITY",n,"no verified external session")
   self.db.execute("COMMIT")
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
  except sqlite3.OperationalError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("store busy") from e
  except sqlite3.DatabaseError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def start_with_ack(self,task_id,worker_id,lease_id,*,ack_details,now=None):
  """Atomically persist ACK truth and the RUNNING transition."""
  n=self.now(now)
  try:
   self.db.execute("BEGIN IMMEDIATE");w=self.db.execute("SELECT * FROM workers WHERE worker_id=?",(worker_id,)).fetchone()
   if not w or n-w["last_heartbeat"]>w["heartbeat_sla"] or w["last_heartbeat"]>n+1:raise BlockedError("cannot acknowledge")
   changed=self.db.execute("UPDATE tasks SET state='RUNNING',updated_at=? WHERE task_id=? AND state='LEASED' AND assigned_worker_id=? AND lease_id=? AND lease_expires_at>?",(n,task_id,worker_id,lease_id,n)).rowcount
   if changed!=1:raise BlockedError("cannot acknowledge")
   self.audit(task_id,"ACKED",n,ack_details);self.audit(task_id,"RUNNING",n,worker_id);self.db.execute("COMMIT")
  except BlockedError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
  except sqlite3.OperationalError as e:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise BlockedError("store busy") from e
  except sqlite3.DatabaseError:
   if self.db.in_transaction:self.db.execute("ROLLBACK")
   raise
 def audit_events(self,task_id): return [dict(x) for x in self.db.execute("SELECT * FROM audit WHERE task_id=? ORDER BY seq",(task_id,))]
 def schedulable_tasks(self,*,limit:int):
  if isinstance(limit,bool) or not isinstance(limit,int) or limit<=0: raise BlockedError("invalid batch size")
  rows=self.db.execute("SELECT * FROM tasks WHERE state IN('QUEUED','WAITING_CAPACITY','RETRYING') AND requires_human_approval=0 AND governance_allowed=1 ORDER BY priority DESC,created_at ASC,task_id ASC LIMIT ?",(limit,)).fetchall()
  return [dict(row) for row in rows]
 def workers(self,*,now=None):
  n=self.now(now); rows=self.db.execute("SELECT worker_id FROM workers ORDER BY worker_id").fetchall()
  return [self.worker_status(row[0],now=n) for row in rows]
 def active_leases(self,*,now=None):
  n=self.now(now); rows=self.db.execute("SELECT task_id,assigned_worker_id,lease_id,lease_expires_at,last_worker_heartbeat,state FROM tasks WHERE state IN('LEASED','RUNNING') AND lease_id IS NOT NULL ORDER BY task_id").fetchall()
  return [{**dict(row),"expired":row["lease_expires_at"]<=n} for row in rows]
 def expired_lease_tasks(self,*,now=None):
  n=self.now(now); return [row[0] for row in self.db.execute("SELECT task_id FROM tasks WHERE state IN('LEASED','RUNNING') AND lease_expires_at<=? ORDER BY task_id",(n,))]
 def state_counts(self):
  counts={state:0 for state in VALID_STATES}
  for row in self.db.execute("SELECT state,count(*) FROM tasks GROUP BY state"):
   if row[0] not in VALID_STATES: raise IntegrityBlockedError("unknown task state")
   counts[row[0]]=row[1]
  return counts
 @staticmethod
 def evidence_hash(payload:bytes)->str:return hashlib.sha256(payload).hexdigest()
