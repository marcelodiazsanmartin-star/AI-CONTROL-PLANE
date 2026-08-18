"""
Provenance Evidence Generator for CONTROL-02.5

Generates reports/CONTROL_02_5_PROVENANCE.json tracking exact Git commit ancestry.
"""

import sys
import json
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent


def verify_ancestry(ancestor_sha: str, descendant_sha: str) -> bool:
    try:
        res = subprocess.run(
            ["git", "-C", str(ROOT_DIR), "merge-base", "--is-ancestor", ancestor_sha, descendant_sha],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        return res.returncode == 0
    except Exception:
        return False


def generate_provenance(code_under_test_sha: str, certification_artifact_commit_sha: str) -> dict:
    reports_dir = ROOT_DIR / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    ancestry_ok = verify_ancestry(code_under_test_sha, certification_artifact_commit_sha)

    prov_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "code_under_test_sha": code_under_test_sha,
        "certification_source_sha": code_under_test_sha,
        "certification_artifact_commit_sha": certification_artifact_commit_sha,
        "provenance_commit_parent_sha": certification_artifact_commit_sha,
        "ancestry_verified": ancestry_ok
    }

    prov_file = reports_dir / "CONTROL_02_5_PROVENANCE.json"
    with open(prov_file, "w", encoding="utf-8") as f:
        json.dump(prov_data, f, indent=2)

    print(f"CONTROL-02.5 Provenance generated at {prov_file}")
    print(f"Ancestry Verified: {ancestry_ok} ({code_under_test_sha[:7]} -> {certification_artifact_commit_sha[:7]})")
    return prov_data


def main():
    parser = argparse.ArgumentParser(description="Generate CONTROL-02.5 Provenance Evidence")
    parser.add_argument("--code-under-test-sha", type=str, required=True, help="Exact Git commit SHA of code under test")
    parser.add_argument("--certification-artifact-commit-sha", type=str, required=True, help="Exact Git commit SHA containing certification artifact")
    args = parser.parse_args()

    generate_provenance(args.code_under_test_sha, args.certification_artifact_commit_sha)


if __name__ == "__main__":
    main()
