"""
Static Adversarial Scan Test: CONTROL-02.5

Scans control plane source code to prove ZERO hardcoded commit SHA trust bypasses,
ZERO author metadata authorization paths, and ZERO hardcoded signature PASS logic.
"""

import re
from pathlib import Path
from config import settings


def test_zero_hardcoded_signature_bypasses():
    src_dir = settings.CONTROL_PLANE_ROOT / "src"
    bypass_patterns = [
        re.compile(r"e927f95"),
        re.compile(r"if\s+commit_sha\s*==\s*['\"]"),
        re.compile(r"in\s+commit_sha"),
        re.compile(r"return\s+True,\s*True,\s*trusted_key"),
        re.compile(r"return\s+True,\s*True,\s*[\"']marcelo")
    ]

    hardcoded_signature_bypass_count = 0
    violating_files = []

    for file_path in src_dir.rglob("*.py"):
        content = file_path.read_text(encoding="utf-8")
        for pattern in bypass_patterns:
            matches = pattern.findall(content)
            if matches:
                hardcoded_signature_bypass_count += len(matches)
                violating_files.append(f"{file_path.name}: {pattern.pattern}")

    assert hardcoded_signature_bypass_count == 0, f"Hardcoded bypasses found in src/: {violating_files}"


def test_production_allowlist_contains_zero_placeholders():
    production_allowlist = getattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", set())
    placeholder_patterns = [
        "test_trusted_key_id_001",
        "CHATGPT_TRUSTED_KEY_FINGERPRINT_01",
        "marcelodiazsanmartin-star",
        "AI-CONTROL-PLANE",
        "VD",
        "CHATGPT",
        "antigravity-bot@google.com",
        "marcelo.diaz.sanmartin@gmail.com"
    ]

    placeholder_count = 0
    found_placeholders = []

    for item in production_allowlist:
        if item in placeholder_patterns or any(p in item for p in ["test", "placeholder", "@"]):
            placeholder_count += 1
            found_placeholders.append(item)

    assert placeholder_count == 0, f"Production allowlist contains placeholder signers: {found_placeholders}"
