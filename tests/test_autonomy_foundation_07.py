"""AF-07 functional lifecycle and fail-closed tests."""
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

import pytest

from config import settings
from src.autonomy.protocol import REAL_PROJECT_MUTATION_ENABLED
from src.autonomy.service import AutonomyServiceHost, CanonicalProvenanceVerifier, ServiceConfig, ServiceInstanceLock, read_status
from src.autonomy.store import AutonomyStore, BlockedError, IntegrityBlockedError

MAIN_BLOB = "7255c679131ab38e9f762ff94371839da72a81e5"

def config_data(tmp_path):
    repo=tmp_path/"protected-repo";repo.mkdir();runtime=tmp_path/"runtime";runtime.mkdir();queue=tmp_path/"queue.jsonl";queue.write_bytes(b"")
    return {"schema_version":1,"service_id":"af07-test","runtime_root":str(runtime.resolve()),"queue_path":str(queue.resolve()),"repository_roots":[str(repo.resolve())],"supported_targets":["ORACLE-AI"],"cadence_seconds":0.01,"backoff_initial_seconds":0.01,"backoff_max_seconds":0.04,"backoff_multiplier":2.0,"max_consecutive_transient_failures":2,"health_stale_seconds":10.0}

def write_config(tmp_path,changes=None):
    data=config_data(tmp_path);data.update(changes or {});path=tmp_path/"service.json";path.write_text(json.dumps(data),encoding="utf-8");return path,data

def test_f01_main_blob_unchanged():
    raw=(Path(__file__).resolve().parents[1]/"main.py").read_bytes().replace(b"\r\n",b"\n");blob=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest();assert blob==MAIN_BLOB

def test_f02_config_missing_fails_closed(tmp_path):
    with pytest.raises(BlockedError):ServiceConfig.load(tmp_path/"missing.json")

def test_f03_config_unknown_field_blocked(tmp_path):
    path,data=write_config(tmp_path);data["extra"]=1;path.write_text(json.dumps(data));
    with pytest.raises(BlockedError):ServiceConfig.load(path)

@pytest.mark.parametrize("payload",[b"{",b"\xff",b"x"*65537,b'{"schema_version":NaN}'],ids=["json","utf8","oversized","nan"])
def test_f04_malformed_oversized_nonfinite_config_blocked(tmp_path,payload):
    path=tmp_path/"bad.json";path.write_bytes(payload)
    with pytest.raises(BlockedError):ServiceConfig.load(path)

@pytest.mark.parametrize("field,value",[("cadence_seconds",True),("cadence_seconds",0),("backoff_initial_seconds",-1),("backoff_max_seconds",9999),("backoff_multiplier",11),("max_consecutive_transient_failures",True),("health_stale_seconds",float("inf"))])
def test_f05_invalid_bounds_blocked(tmp_path,field,value):
    path,data=write_config(tmp_path);data[field]=value;path.write_text(json.dumps(data))
    with pytest.raises(BlockedError):ServiceConfig.load(path)

def test_f06_runtime_root_intersects_repo_blocked(tmp_path):
    data=config_data(tmp_path);data["runtime_root"]=data["repository_roots"][0];path=tmp_path/"bad.json";path.write_text(json.dumps(data))
    with pytest.raises(BlockedError):ServiceConfig.load(path)

def test_f07_config_symlink_blocked(tmp_path,monkeypatch):
    real,_=write_config(tmp_path);link=tmp_path/"link.json"
    try:link.symlink_to(real)
    except OSError:
        link=real;original=Path.is_symlink;monkeypatch.setattr(Path,"is_symlink",lambda self:self==real or original(self))
    with pytest.raises(BlockedError):ServiceConfig.load(link)

def test_f08_unknown_target_blocked(tmp_path):
    path,data=write_config(tmp_path);data["supported_targets"]=["EVIL"];path.write_text(json.dumps(data))
    with pytest.raises(BlockedError):ServiceConfig.load(path)

def test_f09_single_instance_kernel_lock(tmp_path):
    first=ServiceInstanceLock(tmp_path);second=ServiceInstanceLock(tmp_path);assert first.acquire(service_id="s",instance_id="one")
    try:assert second.acquire(service_id="s",instance_id="two") is False
    finally:first.release()
    assert second.acquire(service_id="s",instance_id="two");second.release()

def test_f10_stale_metadata_never_bypasses_held_lock(tmp_path):
    first=ServiceInstanceLock(tmp_path);assert first.acquire(service_id="s",instance_id="one");first.metadata_path.write_text('{"pid":0}');second=ServiceInstanceLock(tmp_path)
    try:assert second.acquire(service_id="s",instance_id="two") is False
    finally:first.release()

def test_f11_startup_cycles_and_clean_restart_are_durable(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);assert AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=3)==0;first=read_status(config);assert first["status"]=="STOPPED" and first["cycle_count"]==3;assert AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=2)==0;second=read_status(config);assert second["cycle_count"]==5 and second["recovery_observed"]==1

class FakeRuntime:
    failures=[]
    def __init__(self,**kwargs):self.store=AutonomyStore(Path(kwargs["runtime_root"])/"autonomy.sqlite")
    def run_once(self):
        if self.failures:
            value=self.failures.pop(0)
            if value:raise value
        return {}

def test_f12_transient_backoff_then_success_resets_counter(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);FakeRuntime.failures=[sqlite3.OperationalError("database is locked"),None];assert AutonomyServiceHost(config,runtime_factory=FakeRuntime,verifier=lambda *a:None).run(cycles=1)==0;assert read_status(config)["consecutive_failures"]==0

def test_f13_transient_limit_crashes(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);FakeRuntime.failures=[TimeoutError(),TimeoutError(),TimeoutError()];assert AutonomyServiceHost(config,runtime_factory=FakeRuntime,verifier=lambda *a:None).run(cycles=1)==5;assert read_status(config)["status"]=="CRASHED"

@pytest.mark.parametrize("error,status,code",[(IntegrityBlockedError("x"),"INTEGRITY_BLOCKED",4),(BlockedError("x"),"BLOCKED",3),(ValueError("x"),"CRASHED",5)])
def test_f14_terminal_errors_do_not_retry(tmp_path,error,status,code):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);FakeRuntime.failures=[error];assert AutonomyServiceHost(config,runtime_factory=FakeRuntime,verifier=lambda *a:None).run(cycles=1)==code;projection=read_status(config);assert projection["status"]==status and projection["cycle_count"]==0

def test_f15_stop_wait_is_interruptible(tmp_path):
    path,_=write_config(tmp_path,{"cadence_seconds":10});config=ServiceConfig.load(path);stop=threading.Event();host=AutonomyServiceHost(config,verifier=lambda *a:None,stop_event=stop);thread=threading.Thread(target=lambda:host.run());thread.start();time.sleep(.1);stop.set();thread.join(2);assert not thread.is_alive() and read_status(config)["status"]=="STOPPED"

def test_f16_health_fresh_and_stale_crash_suspected(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=1);assert read_status(config)["freshness"]=="FRESH";db=sqlite3.connect(config.runtime_root/"autonomy.sqlite");db.execute("UPDATE af07_service_health SET status='RUNNING',heartbeat_at=1");db.commit();db.close();stale=read_status(config,now=100);assert stale["status"]=="CRASH_SUSPECTED" and stale["freshness"]=="STALE"

def test_f17_status_read_only_does_not_change_database(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=1);database=config.runtime_root/"autonomy.sqlite";before=hashlib.sha256(database.read_bytes()).hexdigest();read_status(config);assert before==hashlib.sha256(database.read_bytes()).hexdigest()

def test_f18_provider_absent_never_connected(tmp_path):
    path,_=write_config(tmp_path);config=ServiceConfig.load(path);AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=1);db=sqlite3.connect(config.runtime_root/"autonomy.sqlite");assert db.execute("SELECT count(*) FROM workers").fetchone()[0]==0;db.close()

def test_f19_canonical_verifier_delegates(monkeypatch,tmp_path):
    verifier=CanonicalProvenanceVerifier(tmp_path);marker=object();monkeypatch.setattr(verifier.authenticator,"authenticate",lambda *a:marker);assert verifier(None,None,None) is marker

def test_f20_hard_mutation_flags_remain_false():
    assert REAL_PROJECT_MUTATION_ENABLED is False;assert settings.CONTROL_PLANE_RESTART_PROJECTS is False;assert settings.CONTROL_PLANE_EXECUTE_PROJECT_CODE is False;assert settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False;assert settings.CONTROL_PLANE_WRITE_PROJECTS is False;assert settings.CONTROL_PLANE_CHANGE_STRATEGY is False;assert settings.CONTROL_PLANE_ENABLE_REAL_MONEY is False

def test_f21_production_host_has_no_subprocess_or_project_control():
    source=(Path(__file__).resolve().parents[1]/"src/autonomy/service.py").read_text();assert "subprocess" not in source and "shell=True" not in source;assert all(value not in source for value in ("schtasks","sc.exe","kill_process","restart_project"))
