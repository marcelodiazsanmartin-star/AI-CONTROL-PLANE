"""
Production Signer Manifest Validator: CONTROL-02.5

Validates config/trusted_signers.json against PRODUCTION_TRUSTED_SIGNER_ALLOWLIST.
Recalculates fingerprints directly from public keys using native ssh-keygen / base64 SHA256.
Enforces exact matching: PUBLIC_KEY -> calculated fingerprint -> manifest fingerprint -> allowlist fingerprint.
"""

import os
import json
import base64
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, Any

from config import settings


def get_ssh_keygen_bin() -> str:
    for candidate in [
        r"C:\Program Files\Git\usr\bin\ssh-keygen.exe",
        r"C:\Program Files (x86)\Git\usr\bin\ssh-keygen.exe",
        "ssh-keygen"
    ]:
        try:
            res = subprocess.run([candidate, "-?"], capture_output=True, text=True)
            if res.returncode in (0, 1):
                return candidate
        except Exception:
            pass
    return "ssh-keygen"


def compute_ssh_public_key_fingerprint(public_key_str: str) -> str:
    """
    Computes standard SHA256 base64 SSH key fingerprint from public key text string.
    Uses ssh-keygen if available, or native Python base64 SHA256 fallback.
    """
    try:
        parts = public_key_str.strip().split()
        if len(parts) >= 2:
            raw_b64 = parts[1]
            key_bytes = base64.b64decode(raw_b64)
            digest = hashlib.sha256(key_bytes).digest()
            fp_b64 = base64.b64encode(digest).decode("utf-8").rstrip("=")
            return f"SHA256:{fp_b64}"
    except Exception:
        pass

    # Native ssh-keygen execution fallback
    try:
        ssh_bin = get_ssh_keygen_bin()
        tmp_file = Path("tmp_pub_key.pub")
        tmp_file.write_text(public_key_str, encoding="utf-8")
        res = subprocess.run([ssh_bin, "-l", "-f", str(tmp_file)], capture_output=True, text=True, check=True)
        tmp_file.unlink(missing_ok=True)
        return res.stdout.strip().split()[1]
    except Exception:
        pass

    return "INVALID_FINGERPRINT"


def validate_production_signers(root_dir: Path = None) -> Dict[str, Any]:
    if root_dir is None:
        root_dir = settings.CONTROL_PLANE_ROOT

    manifest_file = root_dir / "config" / "trusted_signers.json"
    allowlist = getattr(settings, "PRODUCTION_TRUSTED_SIGNER_ALLOWLIST", set())

    signer_count = len(allowlist)
    if signer_count == 0:
        return {
            "production_signer_count": 0,
            "production_signers_validated": 0,
            "production_invalid_signer_count": 0,
            "production_placeholder_signer_count": 0,
            "production_signer_manifest_valid": False,
            "production_signer_public_key_verified": False,
            "error": "PRODUCTION_SIGNER_NOT_PROVISIONED"
        }

    if not manifest_file.exists():
        return {
            "production_signer_count": signer_count,
            "production_signers_validated": 0,
            "production_invalid_signer_count": signer_count,
            "production_placeholder_signer_count": 0,
            "production_signer_manifest_valid": False,
            "production_signer_public_key_verified": False,
            "error": "MANIFEST_FILE_NOT_FOUND"
        }

    try:
        manifest_data = json.loads(manifest_file.read_text(encoding="utf-8"))
        records = manifest_data.get("signers", [])

        validated_count = 0
        invalid_count = 0
        placeholder_count = 0
        manifest_valid = True
        pk_verified = True

        placeholder_patterns = ["test", "placeholder", "CHATGPT", "marcelo", "demo", "sample"]

        for fp in allowlist:
            # Check if fp is a placeholder
            if any(p in fp.lower() for p in placeholder_patterns):
                placeholder_count += 1
                invalid_count += 1
                manifest_valid = False
                continue

            # Find matching record in manifest
            matching_record = None
            for rec in records:
                if rec.get("fingerprint") == fp:
                    matching_record = rec
                    break

            if not matching_record:
                invalid_count += 1
                manifest_valid = False
                continue

            # Validate record attributes
            if matching_record.get("status") != "ACTIVE" or matching_record.get("purpose") != "CONTROL_PLANE_DIRECTIVE_SIGNING":
                invalid_count += 1
                manifest_valid = False
                continue

            public_key = matching_record.get("public_key", "")
            calculated_fp = compute_ssh_public_key_fingerprint(public_key)

            if calculated_fp != fp:
                invalid_count += 1
                pk_verified = False
                manifest_valid = False
                continue

            validated_count += 1

        all_ok = (
            signer_count >= 1 and
            validated_count == signer_count and
            invalid_count == 0 and
            placeholder_count == 0 and
            manifest_valid is True and
            pk_verified is True
        )

        return {
            "production_signer_count": signer_count,
            "production_signers_validated": validated_count,
            "production_invalid_signer_count": invalid_count,
            "production_placeholder_signer_count": placeholder_count,
            "production_signer_manifest_valid": manifest_valid,
            "production_signer_public_key_verified": pk_verified,
            "error": None if all_ok else "PRODUCTION_SIGNER_VALIDATION_FAILED"
        }
    except Exception as e:
        return {
            "production_signer_count": signer_count,
            "production_signers_validated": 0,
            "production_invalid_signer_count": signer_count,
            "production_placeholder_signer_count": 0,
            "production_signer_manifest_valid": False,
            "production_signer_public_key_verified": False,
            "error": str(e)
        }
