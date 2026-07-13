"""Controlled vocabularies for release assurance decisions."""

from enum import StrEnum


class ReleaseDecision(StrEnum):
    PASS = "pass"
    CONDITIONAL_PASS = "conditional_pass"
    WARN = "warn"
    BLOCK = "block"


class RuleOutcome(StrEnum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    NOT_APPLICABLE = "not_applicable"
    SUPPRESSED = "suppressed"
    DEFERRED = "deferred"


class DueStatus(StrEnum):
    WITHIN_SLA = "within_sla"
    DUE_SOON = "due_soon"
    OVERDUE = "overdue"
    NOT_APPLICABLE = "not_applicable"


class FixStatus(StrEnum):
    FIX_AVAILABLE = "fix_available"
    NO_FIX_AVAILABLE = "no_fix_available"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"
