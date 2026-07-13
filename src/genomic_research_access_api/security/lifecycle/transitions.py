"""Lifecycle transition operations."""

from __future__ import annotations

from genomic_research_access_api.security.lifecycle.audit import history_entry
from genomic_research_access_api.security.lifecycle.config import DEFAULT_TIMESTAMP
from genomic_research_access_api.security.lifecycle.enums import VulnerabilityStatus
from genomic_research_access_api.security.lifecycle.models import (
    VerificationRecord,
    VulnerabilityRecord,
)
from genomic_research_access_api.security.lifecycle.state_machine import validate_transition


def transition_record(
    record: VulnerabilityRecord,
    to_status: VulnerabilityStatus,
    *,
    actor_role: str,
    reason: str,
    timestamp: str = DEFAULT_TIMESTAMP,
    verification: VerificationRecord | None = None,
    closure_evidence: str | None = None,
    active_exception: bool = False,
    evidence_reference: str | None = None,
) -> VulnerabilityRecord:
    validate_transition(
        record,
        to_status,
        reason=reason,
        verification_passed=verification.passed if verification else None,
        closure_evidence=closure_evidence,
        has_active_exception=active_exception,
        false_positive_evidence=evidence_reference,
    )
    previous = str(record.status)
    updated = record.model_copy(deep=True)
    target = str(to_status)
    if previous == "resolved" and target == "in_remediation":
        updated.verification_status = "failed"
    if target == "verified":
        updated.verified_at = timestamp
        updated.verification_status = "passed"
        updated.verification_method = (
            str(verification.verification_method) if verification else None
        )
        updated.verification_reference = (
            verification.verification_reference if verification else None
        )
    if target == "closed":
        updated.closed_at = timestamp
        updated.closure_evidence = closure_evidence
    if target == "assigned":
        updated.assigned_at = timestamp
    if target == "in_remediation":
        updated.remediation_started_at = timestamp
    if target == "resolved":
        updated.resolved_at = timestamp
    if previous == "closed" and target == "assigned":
        updated.reopened_count += 1
    updated.previous_status = VulnerabilityStatus(previous)
    updated.status = to_status
    updated.updated_at = timestamp
    updated.history.append(
        history_entry(
            vulnerability_id=updated.vulnerability_id,
            event_type="transition",
            from_status=previous,
            to_status=target,
            actor_role=actor_role,
            reason=reason,
            timestamp=timestamp,
            evidence_reference=evidence_reference,
        )
    )
    return updated
