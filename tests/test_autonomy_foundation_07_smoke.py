"""Authorized disposable foreground service smokes."""
import json
import subprocess
import sys
import time
from pathlib import Path

from src.autonomy.service import ServiceConfig, read_status

def make_config(tmp_path,cadence=0.01):
    runtime=tmp_path/"runtime";runtime.mkdir();queue=tmp_path/"queue.jsonl";queue.write_bytes(b"");repo=Path(__file__).resolve().parents[1]
    data={"schema_version":1,"service_id":"af07-smoke","runtime_root":str(runtime.resolve()),"queue_path":str(queue.resolve()),"repository_roots":[str(repo.resolve())],"supported_targets":["ORACLE-AI"],"cadence_seconds":cadence,"backoff_initial_seconds":0.01,"backoff_max_seconds":0.1,"backoff_multiplier":2.0,"max_consecutive_transient_failures":2,"health_stale_seconds":5.0}
    path=tmp_path/"service.json";path.write_text(json.dumps(data),encoding="utf-8");return path,ServiceConfig.load(path)

def run_child(path,cycles):
    return subprocess.run([sys.executable,"-m","src.autonomy.service","--config",str(path),"--cycles",str(cycles)],cwd=Path(__file__).resolve().parents[1],capture_output=True,text=True,timeout=20,shell=False)

def test_smoke_1_bounded_foreground_three_cycles(tmp_path):
    path,config=make_config(tmp_path);result=run_child(path,3);assert result.returncode==0;status=read_status(config);assert status["status"]=="STOPPED" and status["cycle_count"]==3

def test_smoke_2_restart_monotonic_cycles(tmp_path):
    path,config=make_config(tmp_path);assert run_child(path,2).returncode==0;first=read_status(config)["cycle_count"];assert run_child(path,2).returncode==0;second=read_status(config)["cycle_count"];assert (first,second)==(2,4)

def test_smoke_3_second_child_blocked_by_single_instance(tmp_path):
    path,config=make_config(tmp_path,cadence=1.0);root=Path(__file__).resolve().parents[1]
    first=subprocess.Popen([sys.executable,"-m","src.autonomy.service","--config",str(path),"--cycles","100"],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,shell=False)
    try:
        deadline=time.time()+10
        while time.time()<deadline and not (config.runtime_root/"af07.service.owner.json").exists():time.sleep(.05)
        second=run_child(path,1);assert second.returncode==3
    finally:
        first.terminate();first.wait(timeout=10)
