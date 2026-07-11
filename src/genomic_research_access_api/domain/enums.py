"""Controlled domain enumerations."""

from enum import StrEnum


class DatasetStatus(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"


class SensitivityClassification(StrEnum):
    SYNTHETIC_CONTROLLED = "synthetic_controlled"
    SYNTHETIC_RESTRICTED = "synthetic_restricted"


class AccessLevel(StrEnum):
    METADATA_ONLY = "metadata_only"
    AGGREGATE_ANALYSIS = "aggregate_analysis"
    CONTROLLED_EXPORT = "controlled_export"


class AccessRequestStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"


class ActorRole(StrEnum):
    RESEARCHER = "researcher"
    APPROVER = "approver"
    DATA_CUSTODIAN = "data_custodian"
    SECURITY_AUDITOR = "security_auditor"
    APPLICATION_ADMIN = "application_admin"


class AuditEventType(StrEnum):
    AUTHENTICATION_SUCCEEDED = "authentication_succeeded"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORISATION_DENIED = "authorisation_denied"
    DATASET_VIEWED = "dataset_viewed"
    ACCESS_REQUEST_SUBMITTED = "access_request_submitted"
    ACCESS_REQUEST_VIEWED = "access_request_viewed"
    ACCESS_REQUEST_APPROVED = "access_request_approved"
    ACCESS_REQUEST_REJECTED = "access_request_rejected"
    SELF_APPROVAL_DENIED = "self_approval_denied"
    INVALID_WORKFLOW_TRANSITION_ATTEMPTED = "invalid_workflow_transition_attempted"
    AUDIT_EVENTS_VIEWED = "audit_events_viewed"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
