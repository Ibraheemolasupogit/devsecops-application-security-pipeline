"""Controlled vocabulary for vulnerability lifecycle governance."""

from enum import StrEnum


class VulnerabilityStatus(StrEnum):
    DETECTED = "detected"
    VALIDATED = "validated"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    DEFERRED = "deferred"


class ExceptionStatus(StrEnum):
    REQUESTED = "requested"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CLOSED = "closed"


class ExceptionDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    REVOKE = "revoke"
    EXTEND = "extend"
    CLOSE = "close"


class VerificationMethod(StrEnum):
    SCANNER_RESCAN = "scanner_rescan"
    UNIT_TEST = "unit_test"
    SECURITY_TEST = "security_test"
    MANUAL_CODE_REVIEW = "manual_code_review"
    CONFIGURATION_REVIEW = "configuration_review"
    INFRASTRUCTURE_VALIDATION = "infrastructure_validation"
    DEPENDENCY_VERSION_CHECK = "dependency_version_check"
    CONTAINER_RESCAN = "container_rescan"
