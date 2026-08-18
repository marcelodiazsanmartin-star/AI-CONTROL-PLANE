"""
Directive JSON Schema & Structural Validator

Enforces strict schema compliance for inbound directives.
No missing required field may be silently defaulted.
"""

import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
from config import settings


REQUIRED_DIRECTIVE_FIELDS = [
    "directive_version",
    "directive_id",
    "project",
    "target_project",
    "target_stage",
    "action_type",
    "action",
    "created_at",
    "expires_at",
    "issued_by",
    "source_repository",
    "source_branch",
    "source_commit_sha",
    "requires_human_approval",
    "allowed_scope",
    "preconditions",
    "success_criteria",
    "failure_policy",
    "rollback_policy",
    "payload"
]


class DirectiveSchemaValidator:
    def __init__(self, schema_path: Optional[Path] = None):
        self.schema_path = schema_path or (settings.CONTROL_PLANE_ROOT / "directives" / "schema" / "directive.schema.json")
        self.schema_data = None
        if self.schema_path.exists():
            try:
                self.schema_data = json.loads(self.schema_path.read_text(encoding="utf-8"))
            except Exception:
                pass

    def validate(self, raw_data: Any) -> Tuple[bool, str]:
        if not isinstance(raw_data, dict):
            return False, "SCHEMA_INVALID: Directive content is not a valid JSON object"

        missing_fields = [f for f in REQUIRED_DIRECTIVE_FIELDS if f not in raw_data]
        if missing_fields:
            return False, f"SCHEMA_INVALID: Missing required directive fields: {', '.join(missing_fields)}"

        # Type checks for mandatory fields
        string_fields = [
            "directive_version", "directive_id", "project", "target_project",
            "target_stage", "action_type", "action", "created_at", "expires_at",
            "issued_by", "source_repository", "source_branch", "source_commit_sha",
            "failure_policy", "rollback_policy"
        ]
        for sf in string_fields:
            if not isinstance(raw_data.get(sf), str) or not raw_data.get(sf).strip():
                return False, f"SCHEMA_INVALID: Field '{sf}' must be a non-empty string"

        if not isinstance(raw_data.get("requires_human_approval"), bool):
            return False, "SCHEMA_INVALID: Field 'requires_human_approval' must be a boolean"

        if not isinstance(raw_data.get("allowed_scope"), list):
            return False, "SCHEMA_INVALID: Field 'allowed_scope' must be a list"

        dict_fields = ["preconditions", "success_criteria", "payload"]
        for df in dict_fields:
            if not isinstance(raw_data.get(df), dict):
                return False, f"SCHEMA_INVALID: Field '{df}' must be a JSON object (dict)"

        return True, "SCHEMA_VALID"
