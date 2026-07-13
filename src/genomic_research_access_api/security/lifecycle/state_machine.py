"""Strict lifecycle state machine."""

from __future__ import annotations

from genomic_research_access_api.security.lifecycle.config import load_config
from genomic_research_access_api.security.lifecycle.enums import VulnerabilityStatus
from genomic_research_access_api.security.lifecycle.models import VulnerabilityRecord


def valid_transition_pairs() -> set[tuple[str, str]]:
    return {
        (str(item[0]), str(item[1]))
        for item in load_config("transition-rules.yaml")["valid_transitions"]
    }


def valid_transition_count() -> int:
    return len(valid_transition_pairs())


def validate_transition(
    record: VulnerabilityRecord,
    to_status: VulnerabilityStatus,
    *,
    reason: str,
    verification_passed: bool | None = None,
    closure_evidence: str | None = None,
    has_active_exception: bool = False,
    false_positive_evidence: str | None = None,
) -> None:
    from_status = str(record.status)
    target = str(to_status)
    if (from_status, target) not in valid_transition_pairs():
        raise ValueError(f"invalid lifecycle transition: {from_status} -> {target}")
    if from_status == "detected" and target == "closed":
        raise ValueError("detected findings cannot move directly to closed")
    if target == "closed" and (record.verification_status != "passed" or not closure_evidence):
        raise ValueError("closed findings require successful verification and closure evidence")
    if from_status == "resolved" and target == "verified" and verification_passed is not True:
        raise ValueError("resolved findings require a passing verification record before verified")
    if target == "risk_accepted" and not has_active_exception:
        raise ValueError("risk accepted findings require an active approved exception")
    if target == "false_positive" and not false_positive_evidence:
        raise ValueError("false positives require reviewer evidence")
    if target == "deferred" and (
        not record.remediation_owner or not reason or not record.review_date
    ):
        raise ValueError("deferred findings require owner, reason and review date")
    if (
        target in {"assigned", "in_remediation"}
        and record.severity in {"critical", "high"}
        and (not record.technical_owner or record.technical_owner == "unowned")
    ):
        raise ValueError("critical and high findings require owners before assignment")
