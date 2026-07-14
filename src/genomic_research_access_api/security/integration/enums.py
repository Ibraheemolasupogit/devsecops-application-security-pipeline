"""Consumer-neutral integration enums."""

from __future__ import annotations

from enum import StrEnum


class ConsumerStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    IN_REMEDIATION = "in_remediation"
    RESOLVED = "resolved"
    VERIFIED = "verified"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    DEFERRED = "deferred"


class CompatibilityStatus(StrEnum):
    COMPATIBLE = "compatible"
    COMPATIBLE_WITH_WARNINGS = "compatible_with_warnings"
    INCOMPATIBLE = "incompatible"
