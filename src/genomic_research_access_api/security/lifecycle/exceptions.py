"""Security exception governance."""

from __future__ import annotations

from datetime import date

from genomic_research_access_api.security.findings.identifiers import stable_hash
from genomic_research_access_api.security.lifecycle.config import load_config
from genomic_research_access_api.security.lifecycle.enums import ExceptionStatus
from genomic_research_access_api.security.lifecycle.models import SecurityException


def exception_id(vulnerability_id: str, kind: str) -> str:
    return "EXC-" + stable_hash({"vulnerability_id": vulnerability_id, "kind": kind}, length=12)


def required_approval_roles(severity: str) -> list[str]:
    policy = load_config("exception-policy.yaml")
    return list(policy["approval_roles"].get(severity, policy["approval_roles"]["unknown"]))


def maximum_duration_days(severity: str) -> int:
    policy = load_config("exception-policy.yaml")
    return int(
        policy["maximum_duration_days"].get(severity, policy["maximum_duration_days"]["unknown"])
    )


def exception_expiry_status(exception: SecurityException, as_of_date: str) -> str:
    status = str(exception.status)
    if status in {ExceptionStatus.REVOKED, ExceptionStatus.REJECTED, ExceptionStatus.CLOSED}:
        return status
    if not exception.expiry_date:
        return "invalid"
    days = (date.fromisoformat(exception.expiry_date) - date.fromisoformat(as_of_date)).days
    if days < 0:
        return "expired"
    soon_days = int(load_config("lifecycle-policy.yaml")["exception_expiring_soon_days"])
    return "expiring_soon" if days <= soon_days else "active"


def validate_exception(exception: SecurityException, severity: str, as_of_date: str) -> None:
    if not exception.scope or exception.vulnerability_id not in exception.scope:
        raise ValueError(f"exception scope must identify vulnerability: {exception.exception_id}")
    status = str(exception.status)
    if status in {ExceptionStatus.ACTIVE, ExceptionStatus.APPROVED}:
        if not exception.approved_at or not exception.effective_from or not exception.expiry_date:
            raise ValueError(f"approved exception requires dates: {exception.exception_id}")
        approved = date.fromisoformat(exception.approved_at[:10])
        expiry = date.fromisoformat(exception.expiry_date)
        if expiry <= approved:
            raise ValueError(f"exception expiry must be after approval: {exception.exception_id}")
        if (expiry - approved).days > maximum_duration_days(severity):
            raise ValueError(f"exception exceeds maximum duration: {exception.exception_id}")
        required = set(required_approval_roles(severity))
        if not required.issubset(set(exception.approver_roles)):
            raise ValueError(f"exception missing required approvals: {exception.exception_id}")
    if exception_expiry_status(exception, as_of_date) == "expired" and status == "active":
        raise ValueError(f"expired exception must not remain active: {exception.exception_id}")
