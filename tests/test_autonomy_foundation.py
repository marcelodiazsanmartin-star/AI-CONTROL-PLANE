"""AF-00 functional and adversarial verification on disposable SQLite roots."""
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from src.autonomy import AutonomyStore, BlockedError, IntegrityBlockedError

def store(tmp_path): return AutonomyStore(tmp_path/"af00.sqlite")
def task(s, ident="t", **kw): return s.create_task(task_id=ident,directive_id="d-"+ident,target_project="P",capability="C",governance_allowed=True,retry_budget=1,now=100,**kw)
def worker(s, ident="w", **kw): return s.register_worker(worker_id=ident,kind="local-test",capabilities=["C"],targets=["P"],heartbeat_sla=10,capacity=1,now=100,**kw)
def leased(s, ident="t"):
 task(s,ident); worker(s); return s.claim(ident,"w",now=100,lease_seconds=10)

def test_functional_lifecycle_idempotency_and_reopen(tmp_path):
 s=store(tmp_path); a=task(s); assert a["state"]=="QUEUED"; assert task(s)["task_id"]=="t"; worker(s); lease=s.claim("t","w",now=100); s.close()
 s=store(tmp_path); assert s.task("t")["lease_id"]==lease["lease_id"]

def test_functional_routing_heartbeat_capacity_and_human(tmp_path):
 s=store(tmp_path); task(s); assert s.route_or_wait("t",now=100) is None; assert s.task("t")["state"]=="WAITING_CAPACITY"
 worker(s); assert s.route_or_wait("t",now=100)=="w"; assert s.worker_status("w",now=111)["status"]=="STALE"
 task(s,"h",requires_human_approval=True); pytest.raises(BlockedError,s.claim,"h","w",now=100)

def test_functional_renew_retry_evidence_and_terminal(tmp_path):
 s=store(tmp_path); l=leased(s); assert s.renew("t","w",l["lease_id"],now=101)>101
 s.fail_attempt("t","w",l["lease_id"],reason="temporary",now=102); assert s.task("t")["state"]=="RETRYING"
 l=s.claim("t","w",now=103); s.submit_result("t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=104)
 s.complete_after_review("t",evidence_valid=True,now=105); assert s.task("t")["state"]=="COMPLETED"; pytest.raises(BlockedError,s.claim,"t","w",now=106)

def test_functional_retry_survives_restart_and_exhausts(tmp_path):
 s=store(tmp_path); l=leased(s); s.fail_attempt("t","w",l["lease_id"],reason="x",now=101); s.close(); s=store(tmp_path)
 l=s.claim("t","w",now=102); s.fail_attempt("t","w",l["lease_id"],reason="x",now=103); assert s.task("t")["state"]=="DEAD_LETTER"

def test_a01_concurrent_double_claim_blocked(tmp_path):
 s=store(tmp_path); task(s); worker(s,"w1"); worker(s,"w2")
 def claim(w):
  x=AutonomyStore(tmp_path/"af00.sqlite")
  try: x.claim("t",w,now=100); return "OK"
  except BlockedError:return "BLOCKED"
  finally:x.close()
 with ThreadPoolExecutor(max_workers=2) as p: results=list(p.map(claim,["w1","w2"]))
 assert sorted(results)==["BLOCKED","OK"]

def test_a02_replay_duplicate_task_id(tmp_path):
 s=store(tmp_path); task(s); pytest.raises(BlockedError,s.create_task,task_id="t",directive_id="other",target_project="P",capability="C")
def test_a03_stale_worker_running_attempt(tmp_path):
 s=store(tmp_path); l=leased(s); s.start("t","w",l["lease_id"],now=100); assert s.reconcile_stale_workers(now=111)==["t"]; assert s.task("t")["state"]=="RETRYING"
def test_a04_wrong_lease_owner_renewal(tmp_path):
 s=store(tmp_path); l=leased(s); pytest.raises(BlockedError,s.renew,"t","evil",l["lease_id"],now=101)
def test_a05_expired_lease_after_terminal(tmp_path):
 s=store(tmp_path); l=leased(s); s.submit_result("t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=101); s.complete_after_review("t",evidence_valid=True,now=102); pytest.raises(BlockedError,s.reclaim_expired,"t",now=200)
def test_a06_database_busy_is_blocked(tmp_path):
 s=AutonomyStore(tmp_path/"x.db",busy_timeout_ms=5); task(s); worker(s); lock=sqlite3.connect(tmp_path/"x.db",isolation_level=None); lock.execute("BEGIN IMMEDIATE")
 try: pytest.raises(BlockedError,s.claim,"t","w",now=100)
 finally: lock.execute("ROLLBACK"); lock.close()
def test_a07_corrupt_database_fails_closed(tmp_path):
 p=tmp_path/"x.db"; p.write_bytes(b"not sqlite"); pytest.raises(IntegrityBlockedError,AutonomyStore,p)
def test_a08_unsupported_schema_fails_closed(tmp_path):
 s=store(tmp_path); s.db.execute("UPDATE schema_meta SET version=999"); s.close(); pytest.raises(IntegrityBlockedError,AutonomyStore,tmp_path/"af00.sqlite")
def test_a09_forged_capability_target_mismatch(tmp_path):
 s=store(tmp_path); task(s); s.register_worker(worker_id="w",kind="x",capabilities=["WRONG"],targets=["P"],heartbeat_sla=10,capacity=1,now=100); pytest.raises(BlockedError,s.claim,"t","w",now=100)
def test_a10_waiting_human_routing(tmp_path):
 s=store(tmp_path); task(s,requires_human_approval=True); pytest.raises(BlockedError,s.route_or_wait,"t",now=100)
def test_a11_retry_storm_across_restart(tmp_path):
 s=store(tmp_path); l=leased(s); s.fail_attempt("t","w",l["lease_id"],reason="x",now=101); s.close(); s=store(tmp_path); l=s.claim("t","w",now=102); s.fail_attempt("t","w",l["lease_id"],reason="x",now=103); s.close(); s=store(tmp_path); assert s.task("t")["state"]=="DEAD_LETTER"
@pytest.mark.parametrize("budget",[-1,1_000_001,True,1.5])
def test_a12_invalid_retry_budget(tmp_path,budget):
 s=store(tmp_path); pytest.raises(BlockedError,s.create_task,task_id="t",directive_id="d",target_project="P",capability="C",retry_budget=budget)
def test_a13_future_heartbeat_clock_skew(tmp_path):
 s=store(tmp_path); worker(s); pytest.raises(BlockedError,s.heartbeat,"w",now=100,observed_at=1000)
def test_a14_hostile_strings_are_sanitized(tmp_path):
 s=store(tmp_path); l=leased(s); s.fail_attempt("t","w",l["lease_id"],reason='<script>secret=abc</script>',now=101); value=s.task("t")["terminal_reason"]; assert "<" not in value and "abc" not in value
def test_a15_evidence_free_fake_completion(tmp_path):
 s=store(tmp_path); l=leased(s); pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id=None,sha256=None,now=101); pytest.raises(BlockedError,s.complete_after_review,"t",evidence_valid=True,now=102)
def test_a16_duplicate_evidence_submission(tmp_path):
 s=store(tmp_path); l=leased(s); s.submit_result("t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=101); pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=102)
def test_a17_worker_capacity_overclaim(tmp_path):
 s=store(tmp_path); task(s,"a"); task(s,"b"); worker(s); s.claim("a","w",now=100); pytest.raises(BlockedError,s.claim,"b","w",now=100)
def test_a18_unknown_task_state(tmp_path):
 s=store(tmp_path); task(s); s.db.execute("UPDATE tasks SET state='FUTURE' WHERE task_id='t'"); pytest.raises(IntegrityBlockedError,s.task,"t")
def test_a19_interrupted_transaction_reopen(tmp_path):
 s=store(tmp_path); task(s); s.db.execute("BEGIN IMMEDIATE"); s.db.execute("UPDATE tasks SET state='COMPLETED'"); s.db.execute("ROLLBACK"); s.close(); assert store(tmp_path).task("t")["state"]=="QUEUED"
def test_a20_no_mutation_or_execution_api_reachable(tmp_path):
 s=store(tmp_path); forbidden={"execute_subprocess","write_repository","restart_process","stop_process","place_order","call_provider"}; assert forbidden.isdisjoint(set(dir(s)))
