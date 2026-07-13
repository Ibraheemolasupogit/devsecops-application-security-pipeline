"""Build deterministic vulnerability lifecycle records from canonical findings."""

from __future__ import annotations

from datetime import date
from typing import Any

from genomic_research_access_api.security.findings.identifiers import stable_hash
from genomic_research_access_api.security.findings.utils import read_json
from genomic_research_access_api.security.lifecycle.audit import history_entry
from genomic_research_access_api.security.lifecycle.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    FINDINGS_PATH,
    RELEASE_DECISION_PATH,
    SOURCE_MAP_PATH,
    load_config,
    load_fixture,
)
from genomic_research_access_api.security.lifecycle.enums import ExceptionDecision, ExceptionStatus
from genomic_research_access_api.security.lifecycle.exceptions import (
    exception_expiry_status,
    exception_id,
    maximum_duration_days,
    required_approval_roles,
)
from genomic_research_access_api.security.lifecycle.models import (
    SecurityException,
    VulnerabilityRecord,
)


def vulnerability_id(finding_id: str) -> str:
    return "VUL-" + stable_hash({"finding_id": finding_id}, length=12)


def build_register(
    *,
    as_of_date: str = DEFAULT_AS_OF_DATE,
    timestamp: str = DEFAULT_TIMESTAMP,
) -> tuple[list[VulnerabilityRecord], list[SecurityException], list[dict[str, Any]]]:
    findings = _load_findings()
    source_map = _load_source_map()
    overrides = load_fixture("lifecycle-overrides.yaml")
    false_positive_ids = _selected_finding_ids(findings, overrides["false_positive_selectors"])
    exception_plan = _exception_plan(findings, overrides["risk_acceptance_selectors"])
    exceptions: list[SecurityException] = []
    exception_by_finding: dict[str, SecurityException] = {}

    for finding_id, kind in exception_plan.items():
        finding = next(item for item in findings if item["finding_id"] == finding_id)
        exc = _build_exception(finding, kind, timestamp)
        expiry_status = exception_expiry_status(exc, as_of_date)
        if expiry_status == "expired":
            exc.status = ExceptionStatus.EXPIRED
        exceptions.append(exc)
        exception_by_finding[finding_id] = exc

    records: list[VulnerabilityRecord] = []
    for finding in findings:
        records.append(
            _record_from_finding(
                finding,
                source_map.get(finding["finding_id"], {}),
                timestamp=timestamp,
                as_of_date=as_of_date,
                false_positive=finding["finding_id"] in false_positive_ids,
                exception=exception_by_finding.get(finding["finding_id"]),
            )
        )
    validations = validate_lifecycle(records, exceptions, as_of_date=as_of_date)
    return (
        sorted(records, key=lambda item: item.vulnerability_id),
        sorted(exceptions, key=lambda item: item.exception_id),
        validations,
    )


def validate_lifecycle(
    records: list[VulnerabilityRecord],
    exceptions: list[SecurityException],
    *,
    as_of_date: str = DEFAULT_AS_OF_DATE,
) -> list[dict[str, Any]]:
    findings = {record.finding_id for record in records}
    vulnerabilities = {record.vulnerability_id for record in records}
    if len(vulnerabilities) != len(records):
        raise ValueError("duplicate vulnerability IDs")
    exception_ids = {item.exception_id for item in exceptions}
    if len(exception_ids) != len(exceptions):
        raise ValueError("duplicate exception IDs")
    exc_by_vuln = {item.vulnerability_id: item for item in exceptions}
    errors: list[str] = []

    for record in records:
        if record.finding_id not in findings:
            errors.append(f"invalid finding reference: {record.vulnerability_id}")
        if record.status == "closed" and record.verification_status != "passed":
            errors.append(f"closed without verification: {record.vulnerability_id}")
        if record.status == "resolved" and not record.remediation_reference:
            errors.append(f"resolved without remediation evidence: {record.vulnerability_id}")
        if record.status == "risk_accepted":
            exc = exc_by_vuln.get(record.vulnerability_id)
            if not exc or str(exc.status) != "active":
                errors.append(f"risk accepted without active exception: {record.vulnerability_id}")
        if record.status == "false_positive" and (
            not record.false_positive_reason or not record.closure_evidence
        ):
            errors.append(f"false positive missing reviewer evidence: {record.vulnerability_id}")
        if (
            record.severity in {"critical", "high"}
            and record.status in {"assigned", "in_remediation"}
            and (not record.technical_owner or record.technical_owner == "unowned")
        ):
            errors.append(f"unowned high finding assigned: {record.vulnerability_id}")
        for entry in record.history:
            if entry.vulnerability_id != record.vulnerability_id:
                errors.append(f"history vulnerability mismatch: {record.vulnerability_id}")

    for exc in exceptions:
        if exc.vulnerability_id not in vulnerabilities:
            errors.append(f"exception references unknown vulnerability: {exc.exception_id}")
        if exc.finding_id not in findings:
            errors.append(f"exception references unknown finding: {exc.exception_id}")
        status = exception_expiry_status(exc, as_of_date)
        if status == "expired" and str(exc.status) == "active":
            errors.append(f"expired exception remains active: {exc.exception_id}")
    if errors:
        raise ValueError("\n".join(sorted(errors)))
    return [
        {"status": "valid", "checked_records": len(records), "checked_exceptions": len(exceptions)}
    ]


def _record_from_finding(
    finding: dict[str, Any],
    source_map: dict[str, Any],
    *,
    timestamp: str,
    as_of_date: str,
    false_positive: bool,
    exception: SecurityException | None,
) -> VulnerabilityRecord:
    vid = vulnerability_id(str(finding["finding_id"]))
    status = str(load_config("lifecycle-policy.yaml")["default_initial_status"])
    previous_status: str | None = None
    exception_id_value: str | None = None
    false_positive_reason: str | None = None
    closure_evidence: str | None = None
    review_date: str | None = None
    compensating_control = finding.get("compensating_control")
    residual_risk = "medium"

    if false_positive:
        previous_status = status
        status = "false_positive"
        false_positive_reason = (
            "Reviewed local scanner notice is retained as evidence but does not represent "
            "an application vulnerability."
        )
        closure_evidence = "outputs/security/dynamic/zap-summary.json"
        review_date = as_of_date
        residual_risk = "low"
    if exception:
        exception_id_value = exception.exception_id
        review_date = exception.review_date
        compensating_control = "; ".join(exception.compensating_controls)
        expiry_status = exception_expiry_status(exception, as_of_date)
        if expiry_status in {"active", "expiring_soon"}:
            previous_status = status
            status = "risk_accepted"
            residual_risk = exception.residual_risk
        elif expiry_status == "expired":
            previous_status = "risk_accepted"
            status = "assigned"
            residual_risk = "high"

    history = [
        history_entry(
            vulnerability_id=vid,
            event_type="initialise",
            from_status=None,
            to_status=status,
            actor_role="Product Security",
            reason="Initialised from canonical finding evidence.",
            timestamp=timestamp,
            evidence_reference="outputs/security/findings/deduplicated-findings.json",
            metadata={
                "finding_id": finding["finding_id"],
                "scanner_suppression_id": finding.get("suppression_id"),
            },
        )
    ]
    if exception and str(exception.status) == "expired":
        history.append(
            history_entry(
                vulnerability_id=vid,
                event_type="exception_expired",
                from_status="risk_accepted",
                to_status=status,
                actor_role="Product Security",
                reason="Expired exception reactivated the finding.",
                timestamp=timestamp,
                evidence_reference="outputs/security/lifecycle/security-exceptions.json",
                metadata={"exception_id": exception.exception_id},
            )
        )
    if false_positive:
        history.append(
            history_entry(
                vulnerability_id=vid,
                event_type="false_positive_review",
                from_status="triaged",
                to_status="false_positive",
                actor_role="Product Security",
                reason=str(false_positive_reason),
                timestamp=timestamp,
                evidence_reference=str(closure_evidence),
                metadata={"source_evidence_retained": True},
            )
        )

    return VulnerabilityRecord(
        vulnerability_id=vid,
        finding_id=str(finding["finding_id"]),
        source_finding_ids=list(source_map.get("source_finding_ids", [finding["finding_id"]])),
        title=str(finding["title"]),
        description=str(finding["description"]),
        severity=str(finding["normalised_severity"]),
        priority=finding.get("priority"),
        risk_score=finding.get("risk_score"),
        status=status,
        previous_status=previous_status,
        asset_id=finding.get("asset_id"),
        component=finding.get("component")
        or finding.get("package_name")
        or finding.get("resource"),
        technical_owner=finding.get("technical_owner"),
        risk_owner=finding.get("risk_owner"),
        remediation_owner=finding.get("remediation_owner"),
        squad=finding.get("squad"),
        first_detected=str(finding["first_detected"]),
        last_detected=str(finding["last_detected"]),
        validated_at=timestamp,
        triaged_at=timestamp,
        assigned_at=timestamp if status == "assigned" else None,
        due_date=finding.get("due_date"),
        sla_days=finding.get("remediation_sla_days"),
        overdue=_is_overdue(finding.get("due_date"), as_of_date),
        remediation_plan=str(
            finding.get("remediation_guidance") or "Track and remediate according to policy."
        ),
        remediation_reference=None,
        compensating_control=compensating_control,
        residual_risk=residual_risk,
        verification_status="not_verified",
        closure_evidence=closure_evidence,
        exception_id=exception_id_value,
        false_positive_reason=false_positive_reason,
        review_date=review_date,
        created_at=timestamp,
        updated_at=timestamp,
        history=history,
    )


def _build_exception(finding: dict[str, Any], kind: str, timestamp: str) -> SecurityException:
    vid = vulnerability_id(str(finding["finding_id"]))
    severity = str(finding["normalised_severity"])
    durations = {"active": 19, "expiring": 9, "expired": -1}
    expiry = date(2026, 1, 1).toordinal() + durations[kind]
    expiry_date = date.fromordinal(expiry).isoformat()
    status = ExceptionStatus.ACTIVE if kind in {"active", "expiring"} else ExceptionStatus.EXPIRED
    eid = exception_id(vid, kind)
    history = [
        history_entry(
            vulnerability_id=vid,
            event_type="exception_" + kind,
            actor_role="Product Security",
            reason=f"Controlled {kind} exception fixture for local lifecycle governance.",
            timestamp=timestamp,
            evidence_reference="config/lifecycle/fixtures/lifecycle-overrides.yaml",
            metadata={"exception_id": eid},
        )
    ]
    return SecurityException(
        exception_id=eid,
        vulnerability_id=vid,
        finding_id=str(finding["finding_id"]),
        status=status,
        requested_by_role="Technical Owner",
        technical_owner=str(finding.get("technical_owner") or "Technical Owner"),
        risk_owner=str(finding.get("risk_owner") or "Risk Owner"),
        approver_roles=required_approval_roles(severity),
        business_justification=(
            "Local portfolio demonstration requires explicit tracking of unresolved risk."
        ),
        technical_rationale=(
            "Finding remains visible while a time-bound exception records review context."
        ),
        compensating_controls=[
            str(
                finding.get("compensating_control")
                or "No production deployment; evidence is local only."
            )
        ],
        residual_risk="medium",
        requested_at=timestamp,
        approved_at=timestamp if kind != "expired" else "2025-12-01T00:00:00Z",
        effective_from="2026-01-01" if kind != "expired" else "2025-12-01",
        expiry_date=expiry_date,
        review_date=expiry_date,
        maximum_duration_days=maximum_duration_days(severity),
        environment=str(finding.get("environment") or "not_deployed"),
        scope=f"vulnerability:{vid};finding:{finding['finding_id']}",
        decision=ExceptionDecision.APPROVE,
        decision_reason="Approved as a time-bound local portfolio exception.",
        evidence_references=[
            "outputs/security/findings/deduplicated-findings.json",
            "outputs/security/release/release-gate-decision.json",
        ],
        history=history,
    )


def _selected_finding_ids(
    findings: list[dict[str, Any]], selectors: list[dict[str, Any]]
) -> set[str]:
    selected: set[str] = set()
    for selector in selectors:
        for finding in findings:
            if finding["finding_id"] in selected:
                continue
            if all(
                finding.get(key) == value
                for key, value in selector.items()
                if key
                not in {
                    "name",
                    "exception_kind",
                    "false_positive_reason",
                    "reviewer_role",
                    "supporting_evidence",
                }
            ):
                selected.add(str(finding["finding_id"]))
                break
    return selected


def _exception_plan(
    findings: list[dict[str, Any]], selectors: list[dict[str, Any]]
) -> dict[str, str]:
    plan: dict[str, str] = {}
    for selector in selectors:
        kind = str(selector["exception_kind"])
        for finding in findings:
            if finding["finding_id"] in plan:
                continue
            if all(
                finding.get(key) == value
                for key, value in selector.items()
                if key not in {"name", "exception_kind"}
            ):
                plan[str(finding["finding_id"])] = kind
                break
    return plan


def _load_findings() -> list[dict[str, Any]]:
    payload = read_json(FINDINGS_PATH)
    return list(payload["findings"])


def _load_source_map() -> dict[str, dict[str, Any]]:
    return dict(read_json(SOURCE_MAP_PATH))


def _is_overdue(due_date: str | None, as_of_date: str) -> bool:
    return bool(due_date and due_date < as_of_date)


def release_metadata_by_finding() -> dict[str, dict[str, Any]]:
    decision = read_json(RELEASE_DECISION_PATH)
    metadata: dict[str, dict[str, Any]] = {}
    for status_key, field in [
        ("block", "blocking_finding_ids"),
        ("conditional_pass", "conditional_finding_ids"),
        ("warn", "warning_finding_ids"),
    ]:
        for finding_id in decision.get(field, []):
            metadata[str(finding_id)] = {"release_contribution": status_key}
    return metadata
