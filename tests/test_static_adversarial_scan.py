"""
Static Adversarial Scan Test: CONTROL-02.5

Uses shared scan_authentication_bypasses() from src.directive.scanner
and validate_production_signers() from src.directive.signer_validator.
"""

from config import settings
from src.directive.scanner import scan_authentication_bypasses
from src.directive.signer_validator import validate_production_signers


def test_zero_hardcoded_signature_bypasses():
    res = scan_authentication_bypasses(root_dir=settings.CONTROL_PLANE_ROOT)
    assert res["available"] is True
    assert res["count"] == 0, f"Hardcoded bypasses found in src/directive: {res['violations']}"


def test_production_allowlist_contains_zero_placeholders():
    res = validate_production_signers(root_dir=settings.CONTROL_PLANE_ROOT)
    assert res["production_signer_count"] >= 1
    assert res["production_placeholder_signer_count"] == 0
    assert res["production_invalid_signer_count"] == 0
    assert res["production_signer_manifest_valid"] is True
    assert res["production_signer_public_key_verified"] is True
