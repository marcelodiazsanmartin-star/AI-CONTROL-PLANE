"""
Execution Evidence Reconciliation Module: CONTROL-02.5 Block 1

Reconciles execution evidence across mandatory required sources:
1. directives/runtime/execution_queue.jsonl
2. directives/runtime/consumed_directives.jsonl
3. directives/ack/*.json

Enforces fail-closed validation: missing sources, corrupt JSON, contradictory states,
or unclassifiable mutation types result in fail-closed returns with mutating_directives_executed = None.
Only explicitly EXECUTED directives (not QUEUED, ACCEPTED, REJECTED, WAITING_HUMAN) are counted.
"""

import json
from pathlib import Path
from typing import Dict, Any, Set

from config import settings

NON_EXECUTION_STATES = {
    "ACCEPTED", "REJECTED", "WAITING_HUMAN", "QUEUED",
    "SUBMITTED", "PENDING", "RECEIVED", "VALIDATED"
}

EXECUTION_STATES = {
    "EXECUTED", "COMPLETED"
}

KNOWN_READ_ONLY_ACTIONS = {
    "STATUS_REQUEST", "AUDIT_REQUEST", "READ_ONLY_ANALYSIS",
    "GENERATE_REPORT", "RUN_CONTROL_PLANE_TESTS",
    "RUN_READ_ONLY_OBSERVATION", "PREPARE_NEXT_STAGE", "NO_OP"
}

KNOWN_MUTATING_ACTIONS = {
    "MUTATE", "TARGET_MUTATION", "DESTRUCTIVE", "EXECUTE_RECOVERY"
}


def is_explicitly_executed(item: dict) -> bool:
    if item.get("executed") is True:
        return True
    if item.get("execution_status") in EXECUTION_STATES:
        return True
    if item.get("status") in EXECUTION_STATES:
        return True
    if item.get("state") in EXECUTION_STATES:
        return True
    if item.get("decision") in EXECUTION_STATES:
        return True
    return False


def is_explicitly_not_executed(item: dict) -> bool:
    if item.get("executed") is False:
        return True
    if item.get("status") in NON_EXECUTION_STATES:
        return True
    if item.get("decision") in NON_EXECUTION_STATES:
        return True
    if item.get("state") in NON_EXECUTION_STATES:
        return True
    return False


def determine_mutation_type(item: dict) -> bool | None:
    if "mutating" in item and isinstance(item["mutating"], bool):
        return item["mutating"]

    payload = item.get("directive_payload", {})
    action_type = item.get("action_type") or payload.get("action_type")

    if action_type in KNOWN_READ_ONLY_ACTIONS:
        return False
    if action_type in KNOWN_MUTATING_ACTIONS:
        return True

    return None


def reconcile_execution_evidence(root_dir: Path = None) -> Dict[str, Any]:
    if root_dir is None:
        root_dir = settings.CONTROL_PLANE_ROOT

    runtime_dir = root_dir / "directives" / "runtime"
    acks_dir = root_dir / "directives" / "ack"

    queue_file = runtime_dir / "execution_queue.jsonl"
    consumed_file = runtime_dir / "consumed_directives.jsonl"

    missing_sources = []
    if not queue_file.exists():
        missing_sources.append("directives/runtime/execution_queue.jsonl")
    if not consumed_file.exists():
        missing_sources.append("directives/runtime/consumed_directives.jsonl")

    ack_files = list(acks_dir.glob("*.json")) if acks_dir.exists() else []
    if not acks_dir.exists() or len(ack_files) == 0:
        missing_sources.append("directives/ack/*.json")

    source_count = 3 - len(missing_sources)

    if missing_sources:
        return {
            "available": False,
            "complete": False,
            "consistent": False,
            "source_count": source_count,
            "required_source_count": 3,
            "missing_sources": missing_sources,
            "executed_directive_count": None,
            "executed_directive_ids": [],
            "mutating_directives_executed": None,
            "error": "EXECUTION_EVIDENCE_INCOMPLETE"
        }

    executed_ids: Set[str] = set()
    directive_execution_records: Dict[str, dict] = {}
    mutating_count = 0

    # 1. Parse execution queue
    try:
        with open(queue_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    did = item.get("directive_id")
                    if not did:
                        continue
                    directive_execution_records[did] = item
                    if is_explicitly_executed(item):
                        executed_ids.add(did)
    except Exception:
        return {
            "available": False,
            "complete": False,
            "consistent": False,
            "source_count": source_count,
            "required_source_count": 3,
            "missing_sources": [],
            "executed_directive_count": None,
            "executed_directive_ids": [],
            "mutating_directives_executed": None,
            "error": "EXECUTION_EVIDENCE_CORRUPT"
        }

    # 2. Parse consumed directives ledger
    try:
        with open(consumed_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    did = item.get("directive_id")
                    if not did:
                        continue
                    if did in directive_execution_records:
                        prev = directive_execution_records[did]
                        if is_explicitly_executed(prev) and is_explicitly_not_executed(item):
                            return {
                                "available": True,
                                "complete": True,
                                "consistent": False,
                                "source_count": 3,
                                "required_source_count": 3,
                                "missing_sources": [],
                                "executed_directive_count": None,
                                "executed_directive_ids": [],
                                "mutating_directives_executed": None,
                                "error": "EXECUTION_EVIDENCE_INCONSISTENT"
                            }
                    directive_execution_records[did] = item
                    if is_explicitly_executed(item):
                        executed_ids.add(did)
    except Exception:
        return {
            "available": False,
            "complete": False,
            "consistent": False,
            "source_count": source_count,
            "required_source_count": 3,
            "missing_sources": [],
            "executed_directive_count": None,
            "executed_directive_ids": [],
            "mutating_directives_executed": None,
            "error": "EXECUTION_EVIDENCE_CORRUPT"
        }

    # 3. Parse ACK files
    try:
        for ack_file in ack_files:
            item = json.loads(ack_file.read_text(encoding="utf-8"))
            did = item.get("directive_id")
            if not did:
                continue
            if is_explicitly_executed(item):
                executed_ids.add(did)
    except Exception:
        return {
            "available": False,
            "complete": False,
            "consistent": False,
            "source_count": source_count,
            "required_source_count": 3,
            "missing_sources": [],
            "executed_directive_count": None,
            "executed_directive_ids": [],
            "mutating_directives_executed": None,
            "error": "EXECUTION_EVIDENCE_CORRUPT"
        }

    # 4. Evaluate mutating count for explicitly executed directives ONLY
    for did in executed_ids:
        rec = directive_execution_records.get(did, {})
        is_mut = determine_mutation_type(rec)
        if is_mut is True:
            mutating_count += 1
        elif is_mut is None:
            return {
                "available": True,
                "complete": True,
                "consistent": False,
                "source_count": 3,
                "required_source_count": 3,
                "missing_sources": [],
                "executed_directive_count": None,
                "executed_directive_ids": [],
                "mutating_directives_executed": None,
                "error": "EXECUTION_CLASSIFICATION_UNKNOWN"
            }

    return {
        "available": True,
        "complete": True,
        "consistent": True,
        "source_count": 3,
        "required_source_count": 3,
        "missing_sources": [],
        "executed_directive_count": len(executed_ids),
        "executed_directive_ids": sorted(list(executed_ids)),
        "mutating_directives_executed": mutating_count,
        "error": None
    }
