"""Verification-before-closure helpers."""

from __future__ import annotations

from genomic_research_access_api.security.findings.identifiers import stable_hash
from genomic_research_access_api.security.lifecycle.enums import VerificationMethod
from genomic_research_access_api.security.lifecycle.models import VerificationRecord


def verification_id(vulnerability_id: str, method: str, reference: str) -> str:
    return "VER-" + stable_hash(
        {"vulnerability_id": vulnerability_id, "method": method, "reference": reference}, length=12
    )


def build_verification(
    *,
    vulnerability_id: str,
    verifier_role: str,
    method: VerificationMethod,
    reference: str,
    expected_result: str,
    actual_result: str,
    passed: bool,
    verified_at: str,
    notes: str,
) -> VerificationRecord:
    return VerificationRecord(
        verification_id=verification_id(vulnerability_id, method.value, reference),
        vulnerability_id=vulnerability_id,
        verifier_role=verifier_role,
        verification_method=method,
        verification_reference=reference,
        expected_result=expected_result,
        actual_result=actual_result,
        passed=passed,
        verified_at=verified_at,
        notes=notes,
    )
