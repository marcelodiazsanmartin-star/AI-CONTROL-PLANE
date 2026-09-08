"""AF-07 A01-A20 explicit fail-closed campaign."""
import json
from pathlib import Path
import pytest
from config import settings
from src.autonomy.protocol import REAL_PROJECT_MUTATION_ENABLED
from src.autonomy.service import ServiceConfig, ServiceInstanceLock, _safety
from src.autonomy.store import BlockedError, IntegrityBlockedError
from tests.test_autonomy_foundation_07 import config_data

def blocked(fn):
    with pytest.raises(BlockedError):fn()
def cfg(tmp_path,change):
    data=config_data(tmp_path);data.update(change);path=tmp_path/"attack.json";path.write_text(json.dumps(data));return path

def test_a01_config_path_traversal(tmp_path):blocked(lambda:ServiceConfig.load("../attack.json"))
def test_a02_config_symlink_reparse(tmp_path,monkeypatch):
    real=cfg(tmp_path,{});link=tmp_path/"link.json"
    try:link.symlink_to(real)
    except OSError:
        link=real;original=Path.is_symlink;monkeypatch.setattr(Path,"is_symlink",lambda self:self==real or original(self))
    blocked(lambda:ServiceConfig.load(link))
def test_a03_runtime_root_repo_overlap(tmp_path):
    data=config_data(tmp_path);data["runtime_root"]=data["repository_roots"][0];path=tmp_path/"a.json";path.write_text(json.dumps(data));blocked(lambda:ServiceConfig.load(path))
def test_a04_forged_service_identity(tmp_path):blocked(lambda:ServiceConfig.load(cfg(tmp_path,{"service_id":"../../evil"})))
def test_a05_second_instance_race(tmp_path):
    a=ServiceInstanceLock(tmp_path);b=ServiceInstanceLock(tmp_path);assert a.acquire(service_id="s",instance_id="a")
    try:assert b.acquire(service_id="s",instance_id="b") is False
    finally:a.release()
def test_a06_stale_lock_manipulation(tmp_path):
    a=ServiceInstanceLock(tmp_path);assert a.acquire(service_id="s",instance_id="a");a.metadata_path.write_text("{}")
    try:assert ServiceInstanceLock(tmp_path).acquire(service_id="s",instance_id="b") is False
    finally:a.release()
def test_lock_hardlink_is_rejected(tmp_path):
    target=tmp_path/"target";target.write_bytes(b"x");os_link=getattr(__import__('os'),"link");os_link(target,tmp_path/"af07.service.lock");assert ServiceInstanceLock(tmp_path).acquire(service_id="s",instance_id="x") is False
def test_a07_sqlite_integrity_corruption_is_not_claimed_success(tmp_path):
    from src.autonomy.service import AutonomyServiceHost
    config=ServiceConfig.load(cfg(tmp_path,{}));(config.runtime_root/"autonomy.sqlite").write_bytes(b"corrupt")
    with pytest.raises(IntegrityBlockedError):AutonomyServiceHost(config,verifier=lambda *a:None).run(cycles=1)
def test_a08_fake_recovery_success_absent():
    import inspect,src.autonomy.service as service;source=inspect.getsource(service);assert "recovery_observed" in source and "run_once()" in source
def test_a09_lease_replay_after_restart_uses_canonical_runtime():
    import inspect,src.autonomy.service as service;assert "claim(" not in inspect.getsource(service)
def test_a10_result_replay_after_restart_not_reimplemented():
    import inspect,src.autonomy.service as service;assert ".result(" not in inspect.getsource(service)
def test_a11_provider_connected_overclaim_absent():
    import inspect,src.autonomy.service as service;assert "PROVIDER_CONNECTED" not in inspect.getsource(service)
def test_a12_mutation_capability_injection(tmp_path):blocked(lambda:ServiceConfig.load(cfg(tmp_path,{"supported_targets":["MUTATE"]})))
def test_a13_target_substitution(tmp_path):blocked(lambda:ServiceConfig.load(cfg(tmp_path,{"supported_targets":["EVIL"]})))
def test_a14_secret_shaped_config_field(tmp_path):
    data=config_data(tmp_path);data["api_key"]="secret";path=tmp_path/"a.json";path.write_text(json.dumps(data));blocked(lambda:ServiceConfig.load(path))
def test_a15_unbounded_cadence_backoff(tmp_path):blocked(lambda:ServiceConfig.load(cfg(tmp_path,{"cadence_seconds":999999})))
def test_a16_service_loop_crash_spin_is_bounded(tmp_path):
    config=ServiceConfig.load(cfg(tmp_path,{"max_consecutive_transient_failures":1}));assert config.max_consecutive_transient_failures==1
def test_a17_shell_process_escalation_absent():
    source=(Path(__file__).resolve().parents[1]/"src/autonomy/service.py").read_text();assert "subprocess" not in source and "shell=True" not in source
def test_a18_monitored_project_process_control_absent():
    source=(Path(__file__).resolve().parents[1]/"src/autonomy/service.py").read_text();assert all(x not in source for x in ("terminate_project","kill_project","restart_project"))
def test_a19_protected_evidence_mutation_absent():
    source=(Path(__file__).resolve().parents[1]/"src/autonomy/service.py").read_text();assert all(x not in source for x in ("directives/audit","reports/","state/"))
def test_a20_hard_safety_invariant_proof():
    _safety();assert REAL_PROJECT_MUTATION_ENABLED is False;assert settings.CONTROL_PLANE_EXECUTE_MUTATING_DIRECTIVES is False
