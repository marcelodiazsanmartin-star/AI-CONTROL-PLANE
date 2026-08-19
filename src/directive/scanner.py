"""
Shared Authentication Bypass Scanner: CONTROL-02.5

Scans actual src/directive/**/*.py source code for trust bypasses,
commit SHA specific authorizations, author/committer metadata matching,
and hardcoded signature PASS logic.

Used by both certification evidence generator and adversarial test suite.
"""

import re
from pathlib import Path
from typing import Dict, Any, List


def scan_authentication_bypasses(root_dir: Path = None) -> Dict[str, Any]:
    """
    Scans src/directive/**/*.py for trust bypass patterns.
    """
    if root_dir is None:
        root_dir = Path(__file__).resolve().parent.parent.parent

    src_directive_dir = root_dir / "src" / "directive"
    if not src_directive_dir.exists():
        return {
            "available": False,
            "count": None,
            "violations": [],
            "scanned_files": 0,
            "error": f"Directory not found: {src_directive_dir}"
        }

    bypass_patterns = [
        (re.compile(r"e927f95"), "Hardcoded SHA substring 'e927f95' detected"),
        (re.compile(r"if\s+commit_sha\s*==\s*['\"]"), "SHA-specific equality check detected"),
        (re.compile(r"in\s+commit_sha"), "Commit SHA substring check detected"),
        (re.compile(r"return\s+True,\s*True,\s*trusted_key"), "Hardcoded trusted_key return detected"),
        (re.compile(r"return\s+True,\s*True,\s*[\"']marcelo"), "Hardcoded author identity return detected"),
        (re.compile(r"author_name\s+in\s+settings\.TRUSTED"), "Author metadata matching detected"),
        (re.compile(r"committer_name\s+in\s+settings\.TRUSTED"), "Committer metadata matching detected"),
        (re.compile(r"signature_valid\s*=\s*True\s*#\s*bypass"), "Bypass comment annotation detected")
    ]

    violations: List[str] = []
    scanned_files_count = 0

    try:
        for py_file in src_directive_dir.rglob("*.py"):
            if py_file.name == "scanner.py":
                continue
            scanned_files_count += 1
            content = py_file.read_text(encoding="utf-8")
            for pattern, desc in bypass_patterns:
                matches = pattern.findall(content)
                if matches:
                    violations.append(f"{py_file.relative_to(root_dir)}: {desc} ({len(matches)} match(es))")

        return {
            "available": True,
            "count": len(violations),
            "violations": violations,
            "scanned_files": scanned_files_count,
            "error": None
        }
    except Exception as e:
        return {
            "available": False,
            "count": None,
            "violations": [],
            "scanned_files": scanned_files_count,
            "error": str(e)
        }
