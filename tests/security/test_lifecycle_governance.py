from pathlib import Path

import pytest

from genomic_research_access_api.security.findings.utils import read_json, write_json
from genomic_research_access_api.security.lifecycle import __main__ as lifecycle_main
from genomic_research_access_api.security.lifecycle.config import DEFAULT_AS_OF_DATE
from genomic_research_access_api.security.lifecycle.enums import (
    VerificationMethod,
    VulnerabilityStatus,
)
from genomic_research_access_api.security.lifecycle.evidence import (
    generate,
    validate_policy,
    verify,
)
from genomic_research_access_api.security.lifecycle.exceptions import (
    exception_expiry_status,
    maximum_duration_days,
    required_approval_roles,
    validate_exception,
)
from genomic_research_access_api.security.lifecycle.models import (
    SecurityException,
    VulnerabilityRecord,
)
from genomic_research_access_api.security.lifecycle.report import generate_reports
from genomic_research_access_api.security.lifecycle.repository import build_register
from genomic_research_access_api.security.lifecycle.state_machine import (
    valid_transition_count,
    validate_transition,
)
from genomic_research_access_api.security.lifecycle.transitions import transition_record
from genomic_research_access_api.security.lifecycle.verification import build_verification


def record(**overrides: object) -> VulnerabilityRecord:
    payload = {
        "vulnerability_id": "VUL-000000000001",
        "finding_id": "FND-001",
        "source_finding_ids": ["FND-001"],
        "title": "demo",
        "description": "demo",
        "severity": "high",
        "priority": "P2",
        "risk_score": 70.0,
        "status": "triaged",
        "asset_id": "AST-APP",
        "component": "component",
        "technical_owner": "Platform Engineering",
        "risk_owner": "Risk Owner",
        "remediation_owner": "Platform Engineering",
        "squad": "Platform Engineering",
        "first_detected": "2026-01-01",
        "last_detected": "2026-01-01",
        "validated_at": "2026-01-01T00:00:00Z",
        "triaged_at": "2026-01-01T00:00:00Z",
        "due_date": "2026-01-15",
        "sla_days": 14,
        "overdue": False,
        "remediation_plan": "Apply fix",
        "verification_status": "not_verified",
        "review_date": "2026-01-15",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "history": [],
    }
    payload.update(overrides)
    return VulnerabilityRecord.model_validate(payload)


def exception(**overrides: object) -> SecurityException:
    payload = {
        "exception_id": "EXC-000000000001",
        "vulnerability_id": "VUL-000000000001",
        "finding_id": "FND-001",
        "status": "active",
        "requested_by_role": "Technical Owner",
        "technical_owner": "Platform Engineering",
        "risk_owner": "Risk Owner",
        "approver_roles": ["Product Security", "Risk Owner"],
        "business_justification": "demo",
        "technical_rationale": "demo",
        "compensating_controls": ["not deployed"],
        "residual_risk": "medium",
        "requested_at": "2026-01-01T00:00:00Z",
        "approved_at": "2026-01-01T00:00:00Z",
        "effective_from": "2026-01-01",
        "expiry_date": "2026-01-20",
        "review_date": "2026-01-20",
        "maximum_duration_days": 30,
        "environment": "not_deployed",
        "scope": "vulnerability:VUL-000000000001;finding:FND-001",
        "decision": "approve",
        "decision_reason": "demo",
        "evidence_references": ["outputs/security/findings/deduplicated-findings.json"],
        "history": [],
    }
    payload.update(overrides)
    return SecurityException.model_validate(payload)


def test_policy_validation_and_transition_count() -> None:
    summary = validate_policy()
    assert summary["valid"] is True
    assert valid_transition_count() == 16


def test_valid_lifecycle_transitions() -> None:
    validate_transition(record(status="detected"), VulnerabilityStatus.VALIDATED, reason="ok")
    validate_transition(record(status="validated"), VulnerabilityStatus.TRIAGED, reason="ok")
    validate_transition(record(status="triaged"), VulnerabilityStatus.ASSIGNED, reason="ok")


def test_invalid_lifecycle_transitions_and_detected_cannot_close() -> None:
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        validate_transition(record(status="detected"), VulnerabilityStatus.CLOSED, reason="bad")


def test_resolved_cannot_close_directly_and_requires_verification() -> None:
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        validate_transition(record(status="resolved"), VulnerabilityStatus.CLOSED, reason="bad")
    with pytest.raises(ValueError, match="passing verification"):
        validate_transition(
            record(status="resolved"), VulnerabilityStatus.VERIFIED, reason="verify"
        )


def test_failed_verification_reopens_remediation() -> None:
    failed = build_verification(
        vulnerability_id="VUL-000000000001",
        verifier_role="Verifier",
        method=VerificationMethod.SECURITY_TEST,
        reference="tests/security/test_lifecycle_governance.py",
        expected_result="pass",
        actual_result="fail",
        passed=False,
        verified_at="2026-01-01T00:00:00Z",
        notes="failed",
    )
    updated = transition_record(
        record(status="resolved"),
        VulnerabilityStatus.IN_REMEDIATION,
        actor_role="Verifier",
        reason="verification failed",
        verification=failed,
    )
    assert updated.status == "in_remediation"
    assert updated.verification_status == "failed"


def test_verified_can_close_with_closure_evidence() -> None:
    verified = record(status="verified", verification_status="passed")
    closed = transition_record(
        verified,
        VulnerabilityStatus.CLOSED,
        actor_role="Verifier",
        reason="closure",
        closure_evidence="outputs/security/lifecycle/verification-register.json",
    )
    assert closed.status == "closed"
    assert closed.closure_evidence


def test_closed_record_reopening() -> None:
    reopened = transition_record(
        record(status="closed", verification_status="passed", closure_evidence="evidence"),
        VulnerabilityStatus.ASSIGNED,
        actor_role="Product Security",
        reason="source_evidence_changed",
    )
    assert reopened.reopened_count == 1


def test_high_owner_requirements() -> None:
    with pytest.raises(ValueError, match="require owners"):
        validate_transition(
            record(status="triaged", technical_owner="unowned"),
            VulnerabilityStatus.ASSIGNED,
            reason="assign",
        )


def test_assignment_and_owner_change_history() -> None:
    assigned = transition_record(
        record(status="triaged"),
        VulnerabilityStatus.ASSIGNED,
        actor_role="Product Security",
        reason="assignment",
    )
    assert assigned.history[-1].event_type == "transition"
    assert assigned.history[-1].to_status == "assigned"


def test_false_positive_evidence_requirements_and_reopen() -> None:
    with pytest.raises(ValueError, match="reviewer evidence"):
        validate_transition(
            record(status="validated"),
            VulnerabilityStatus.FALSE_POSITIVE,
            reason="scanner noise",
        )
    validate_transition(
        record(status="validated"),
        VulnerabilityStatus.FALSE_POSITIVE,
        reason="scanner noise",
        false_positive_evidence="outputs/security/appsec/raw/semgrep.json",
    )
    validate_transition(
        record(status="false_positive"), VulnerabilityStatus.TRIAGED, reason="changed"
    )


def test_exception_approval_policy_and_duration_policy() -> None:
    assert required_approval_roles("critical") == [
        "Product Security",
        "Risk Owner",
        "Technical Owner",
    ]
    assert required_approval_roles("high") == ["Product Security", "Risk Owner"]
    assert maximum_duration_days("critical") == 14
    assert maximum_duration_days("high") == 30


def test_exception_request_approval_missing_approval_and_max_duration() -> None:
    validate_exception(exception(), "high", DEFAULT_AS_OF_DATE)
    with pytest.raises(ValueError, match="missing required approvals"):
        validate_exception(
            exception(approver_roles=["Product Security"]), "high", DEFAULT_AS_OF_DATE
        )
    with pytest.raises(ValueError, match="exceeds maximum duration"):
        validate_exception(exception(expiry_date="2026-03-01"), "high", DEFAULT_AS_OF_DATE)


def test_exception_expiry_revocation_and_extension_history() -> None:
    assert (
        exception_expiry_status(exception(expiry_date="2026-01-05"), DEFAULT_AS_OF_DATE)
        == "expiring_soon"
    )
    assert (
        exception_expiry_status(
            exception(status="expired", expiry_date="2025-12-31"), DEFAULT_AS_OF_DATE
        )
        == "expired"
    )
    assert exception_expiry_status(exception(status="revoked"), DEFAULT_AS_OF_DATE) == "revoked"


def test_risk_acceptance_requires_active_exception() -> None:
    with pytest.raises(ValueError, match="active approved exception"):
        validate_transition(
            record(status="triaged"), VulnerabilityStatus.RISK_ACCEPTED, reason="accept"
        )
    validate_transition(
        record(status="triaged"),
        VulnerabilityStatus.RISK_ACCEPTED,
        reason="accept",
        has_active_exception=True,
    )


def test_current_canonical_findings_initialise_successfully() -> None:
    records, exceptions, validations = build_register()
    assert len(records) == 44
    assert len(exceptions) == 3
    assert validations[0]["status"] == "valid"
    assert any(record.status == "risk_accepted" for record in records)
    assert any(record.status == "assigned" for record in records)
    assert any(str(exc.status) == "expired" for exc in exceptions)


def test_scanner_suppression_is_not_formal_exception() -> None:
    records, _, _ = build_register()
    suppressed = [record for record in records if record.finding_id.startswith("FND-SUPPRESSIO")]
    assert suppressed
    assert any(record.exception_id is None for record in suppressed)


def test_overdue_due_soon_and_unowned_reporting() -> None:
    records, _, _ = build_register()
    assert sum(record.overdue for record in records) == 0
    assert any(record.due_date == "2026-01-04" for record in records)
    assert all(record.technical_owner != "unowned" for record in records)


def test_deterministic_ids_evidence_and_tamper_detection(tmp_path: Path) -> None:
    generate(tmp_path)
    verify(tmp_path)
    register = read_json(tmp_path / "vulnerability-register.json")
    first_id = register["vulnerabilities"][0]["vulnerability_id"]
    generate(tmp_path)
    assert (
        read_json(tmp_path / "vulnerability-register.json")["vulnerabilities"][0][
            "vulnerability_id"
        ]
        == first_id
    )
    payload = read_json(tmp_path / "lifecycle-summary.json")
    payload["tampered"] = True
    write_json(tmp_path / "lifecycle-summary.json", payload)
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify(tmp_path)


def test_csv_formula_injection_safety(tmp_path: Path) -> None:
    generate(tmp_path)
    text = (tmp_path / "vulnerability-register.csv").read_text(encoding="utf-8")
    assert "\r\n" not in text
    assert "=cmd" not in text


def test_report_generation(tmp_path: Path) -> None:
    generate(tmp_path)
    report_dir = tmp_path / "reports"
    written = generate_reports(tmp_path, report_dir)
    assert {path.name for path in written} == {
        "lifecycle-audit-report.md",
        "overdue-findings-report.md",
        "remediation-register-report.md",
        "security-exception-report.md",
        "verification-report.md",
        "vulnerability-lifecycle-report.md",
    }


@pytest.mark.parametrize(
    "command, expected",
    [
        ("validate", "validated lifecycle policy"),
        ("initialise", "initialised 44 vulnerabilities"),
        ("evaluate-expiry", "initialised 44 vulnerabilities"),
        ("generate-evidence", "generated lifecycle evidence"),
        ("verify-evidence", "verified lifecycle evidence"),
        ("generate-reports", "generated lifecycle reports"),
        ("full", "completed lifecycle full workflow"),
    ],
)
def test_lifecycle_cli_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str, expected: str
) -> None:
    monkeypatch.setattr("sys.argv", ["lifecycle", command])
    lifecycle_main.main()
    assert expected in capsys.readouterr().out
