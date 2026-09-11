"""Test in a fresh local clone, retaining logs and preserving source evidence.

No source Git mutation, network clone, commit, push, or evidence generator.
Existing crypto tests create signed commits only in their temporary fixtures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

BASE = "33a1655a06e51dc5facfde2737ee0968c69ee27b"
BRANCH = "codex/control-05-trust-anchor-authority"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *args], text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dependencies", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("tests", nargs="*", default=["tests/"])
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1]
    if git(source, "rev-parse", "HEAD") != BASE or git(source, "branch", "--show-current") != BRANCH:
        raise RuntimeError("VALIDATION_SOURCE_IDENTITY_MISMATCH")
    paths = git(source, "ls-files", "-z").split("\0")
    paths += git(source, "ls-files", "--others", "--exclude-standard", "-z").split("\0")
    paths = sorted(set(p for p in paths if p))
    baseline = {p: hashlib.sha256((source / p).read_bytes()).hexdigest() for p in paths if (source / p).is_file()}
    validation = Path(tempfile.mkdtemp(prefix="control05-" + args.label + "-"))
    checkout = validation / "checkout"
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--no-checkout", str(source), str(checkout)], check=True)
    subprocess.run(["git", "-C", str(checkout), "checkout", "--detach", BASE], check=True)
    for relative in baseline:
        target = checkout / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
    # Do not inherit another worktree's embedded Python ._pth in subprocesses.
    executable = Path(sys.executable)
    if os.name == "nt" and (executable.parent / "python312._pth").exists():
        python_dir = validation / "python"
        python_dir.mkdir()
        for binary in executable.parent.iterdir():
            if binary.is_file() and binary.suffix in {".exe", ".dll", ".pyd", ".zip"}:
                shutil.copyfile(binary, python_dir / binary.name)
        (python_dir / "python312._pth").write_text("\n".join([
            "python312.zip", ".", str(checkout), str(executable.parent / "Lib" / "site-packages"),
            str(args.dependencies.resolve()), "import site", ""]), encoding="utf-8")
        executable = python_dir / "python.exe"
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_ALLOW_PROTOCOL"] = "file"
    command = [str(executable), "-B", "-m", "pytest", *args.tests, "-q", "-p", "no:cacheprovider",
               "--basetemp=" + str(validation / "pytest"), "--junitxml=" + str(validation / "junit.xml")]
    print("VALIDATION_DIRECTORY=" + str(validation), flush=True)
    print("VALIDATION_COMMAND=" + json.dumps(command), flush=True)
    with (validation / "pytest.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=checkout, env=env, stdout=log, stderr=subprocess.STDOUT)
    changed = [p for p, sha in baseline.items() if not (source / p).is_file()
               or hashlib.sha256((source / p).read_bytes()).hexdigest() != sha]
    summary = {"label": args.label, "base": BASE, "branch": BRANCH, "exit_code": result.returncode,
               "source_modified_during_validation": changed, "input_hashes": baseline}
    (validation / "validation.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print((validation / "pytest.log").read_text(encoding="utf-8"), flush=True)
    print("SOURCE_MODIFIED_DURING_VALIDATION=" + json.dumps(changed), flush=True)
    return result.returncode or (1 if changed else 0)


if __name__ == "__main__":
    raise SystemExit(main())
