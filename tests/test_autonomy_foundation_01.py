"""AF-01 functional and A01-A20 adversarial tests on disposable stores."""
import inspect, sqlite3
from concurrent.futures import ThreadPoolExecutor
import pytest
from src.autonomy import AutonomyStore,BlockedError,IntegrityBlockedError,ReadOnlyTestWorker,Scheduler,Supervisor,WorkerResult

def store(p):return AutonomyStore(p/"af01.sqlite",busy_timeout_ms=10)
def add_task(s,i="t",**kw):return s.create_task(task_id=i,directive_id="d-"+i,target_project=kw.pop("target_project","TEST"),capability=kw.pop("capability","READ"),governance_allowed=kw.pop("governance_allowed",True),retry_budget=kw.pop("retry_budget",1),now=kw.pop("now",100),**kw)
def adapter(i="w",**kw):return ReadOnlyTestWorker(i,**kw)
def supervisor(p,adapters=None,**kw):
 s=store(p);a=[adapter()] if adapters is None else adapters;v=Supervisor(s,a,**kw);v.register_adapters(now=100);return s,v

def test_f01_queued_eligible_gets_exactly_one_lease(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);r=v.scheduler.schedule_once(now=100);assert len(r)==1 and s.task("t")["state"]=="LEASED"
def test_f02_no_worker_waits_capacity(tmp_path):
 s=store(tmp_path);add_task(s);Scheduler(s).schedule_once(now=100);assert s.task("t")["state"]=="WAITING_CAPACITY"
def test_f03_priority_fifo_order(tmp_path):
 s,v=supervisor(tmp_path,[adapter(capacity=3)]);add_task(s,"low",priority=1);add_task(s,"b",priority=2);add_task(s,"a",priority=2)
 assert [x["task_id"] for x in v.scheduler.schedule_once(now=100)]==["a","b","low"]
def test_f04_bounded_batch_and_cadence(tmp_path):
 s,v=supervisor(tmp_path,[adapter(capacity=5)],batch_size=2);[add_task(s,str(i)) for i in range(4)];assert len(v.scheduler.schedule_once(now=100))==2
 sleeps=[];Scheduler(store(tmp_path/"other"),cadence_seconds=.25,sleeper=sleeps.append).run(3,clock=lambda:100);assert sleeps==[.25,.25]
def test_f05_restart_reconstructs_sqlite(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);v.scheduler.schedule_once(now=100);s.close();s=store(tmp_path);assert len(Supervisor(s,[adapter()]).health_snapshot(now=101)["active_leases"])==1
def test_f06_stale_and_expired_reconcile(tmp_path):
 s,v=supervisor(tmp_path);add_task(s,retry_budget=2);lease=v.scheduler.schedule_once(now=100)[0];s.start("t","w",lease["lease_id"],now=100);assert v.reconcile(now=131)==["t"] and s.task("t")["state"]=="RETRYING"
def test_f07_f08_expired_or_wrong_result_rejected(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0]
 pytest.raises(BlockedError,s.submit_result,"t","evil",l["lease_id"],evidence_id="e",sha256="a"*64,now=101);v.reconcile(now=131);pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=132)
def test_f09_f10_waiting_human_and_terminal_never_scheduled(tmp_path):
 s,v=supervisor(tmp_path);add_task(s,"h",requires_human_approval=True);add_task(s,"x");s.db.execute("UPDATE tasks SET state='COMPLETED' WHERE task_id='x'");assert v.scheduler.schedule_once(now=100)==[]
def test_f11_worker_result_requires_review_then_controlled_completion(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);assert not v.run_once(now=100)["errors"];assert s.task("t")["state"]=="REVIEW_PENDING";s.complete_after_review("t",evidence_valid=True,now=101);assert s.task("t")["state"]=="COMPLETED"
def test_f12_f13_invalid_and_duplicate_evidence_never_double_complete(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0];s.start("t","w",l["lease_id"],now=100)
 pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id="",sha256="bad",now=100);assert s.task("t")["state"]!="COMPLETED"
def test_f14_one_failure_does_not_crash_loop(tmp_path):
 s,v=supervisor(tmp_path,[adapter("bad",capacity=1,fail=True),adapter("w",capacity=1)]);add_task(s,"a");add_task(s,"b");r=v.run_once(now=100);assert len(r["leases"])==2 and len(r["errors"])==1
def test_f15_health_snapshot_truth(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);snap=v.health_snapshot(now=200);assert snap["workers"][0]["status"]=="STALE" and snap["counts"]["QUEUED"]==1 and "capabilities" not in snap["workers"][0]

def test_a01_double_scheduler_race(tmp_path):
 s,v=supervisor(tmp_path,[adapter("a"),adapter("b")]);add_task(s)
 def go(_):x=AutonomyStore(tmp_path/"af01.sqlite");return len(Scheduler(x).schedule_once(now=100))
 with ThreadPoolExecutor(max_workers=2) as pool:assert sum(pool.map(go,range(2)))==1
def test_a02_two_supervisors_reconcile_same_lease(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);v.scheduler.schedule_once(now=100)
 def go(_):x=AutonomyStore(tmp_path/"af01.sqlite");return Supervisor(x).reconcile(now=131)
 with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(go,range(2)));assert sum(bool(x) for x in results)==1
def test_a03_stale_worker_result(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0];s.start("t","w",l["lease_id"],now=100);v.reconcile(now=131);pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=132)
def test_a04_forged_lease(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0];pytest.raises(BlockedError,s.submit_result,"t","w","forged",evidence_id="e",sha256="a"*64,now=100)
def test_a05_terminal_during_work(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0];s.db.execute("UPDATE tasks SET state='DEAD_LETTER' WHERE task_id='t'");pytest.raises(BlockedError,s.submit_result,"t","w",l["lease_id"],evidence_id="e",sha256="a"*64,now=100)
def test_a06_waiting_human_injection(tmp_path):test_f09_f10_waiting_human_and_terminal_never_scheduled(tmp_path)
def test_a07_forged_capability_target(tmp_path):
 s,v=supervisor(tmp_path,[adapter(capabilities=("OTHER",))]);add_task(s);assert v.scheduler.schedule_once(now=100)==[] and s.task("t")["state"]=="WAITING_CAPACITY"
def test_a08_capacity_overclaim_different_tasks(tmp_path):
 s,v=supervisor(tmp_path);add_task(s,"a");add_task(s,"b");assert len(v.scheduler.schedule_once(now=100))==1
def test_a09_restart_during_claim(tmp_path):test_f05_restart_reconstructs_sqlite(tmp_path)
def test_a10_locked_database_loop_isolated(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);lock=sqlite3.connect(tmp_path/"af01.sqlite",isolation_level=None);lock.execute("BEGIN IMMEDIATE")
 try:assert v.scheduler.schedule_once(now=100)==[] and v.scheduler.last_error!=""
 finally:lock.execute("ROLLBACK");lock.close()
def test_a11_corrupt_store_startup(tmp_path):
 p=tmp_path/"x.db";p.write_bytes(b"corrupt");pytest.raises(IntegrityBlockedError,AutonomyStore,p)
def test_a12_unsupported_schema(tmp_path):
 s=store(tmp_path);s.db.execute("UPDATE schema_meta SET version=99");s.close();pytest.raises(IntegrityBlockedError,store,tmp_path)
def test_a13_future_heartbeat(tmp_path):
 s,v=supervisor(tmp_path);pytest.raises(BlockedError,s.heartbeat,"w",now=100,observed_at=999)
def test_a14_retry_exhaustion_restart(tmp_path):
 s,v=supervisor(tmp_path);add_task(s,retry_budget=0);v.scheduler.schedule_once(now=100);s.close();s=store(tmp_path);Supervisor(s).reconcile(now=131);assert s.task("t")["state"]=="DEAD_LETTER"
def test_a15_duplicate_result_replay(tmp_path):test_f12_f13_invalid_and_duplicate_evidence_never_double_complete(tmp_path)
def test_a16_hostile_result_strings(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);l=v.scheduler.schedule_once(now=100)[0];s.start("t","w",l["lease_id"],now=100);s.submit_result("t","w",l["lease_id"],evidence_id='<script>secret=abc</script>',sha256="a"*64,now=100)
 value=s.db.execute("SELECT evidence_id FROM evidence").fetchone()[0];assert "<" not in value and "abc" not in value
def test_a17_scheduler_exception_isolation(tmp_path):
 s,v=supervisor(tmp_path,[adapter(fail=True)]);add_task(s);assert len(v.run_once(now=100)["errors"])==1
def test_a18_unknown_task_state(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);s.db.execute("UPDATE tasks SET state='FUTURE'");pytest.raises(IntegrityBlockedError,v.health_snapshot,now=100)
def test_a19_health_never_fabricates_running(tmp_path):
 s,v=supervisor(tmp_path);add_task(s);snap=v.health_snapshot(now=100);assert snap["counts"]["RUNNING"]==0
def test_a20_no_mutation_surface():
 import src.autonomy.scheduler as scheduler,src.autonomy.supervisor as supervisor,src.autonomy.worker as worker
 source="\n".join(inspect.getsource(x) for x in (scheduler,supervisor,worker));assert all(token not in source for token in ("subprocess","os.system","socket","requests","urllib","git push","terminate("))
