"""Controlled vocabulary for consolidated evidence."""

from enum import StrEnum


class EvidenceDomain(StrEnum):
    THREAT_MODEL = "threat_model"
    API_SECURITY = "api_security"
    INFRASTRUCTURE = "infrastructure"
    APPSEC = "appsec"
    DYNAMIC_SECURITY = "dynamic_security"
    FINDINGS = "findings"
    RELEASE_ASSURANCE = "release_assurance"
    LIFECYCLE = "lifecycle"


class VerificationStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"


class ControlStatus(StrEnum):
    IMPLEMENTED = "implemented"
    IMPLEMENTED_AS_CODE = "implemented_as_code"
    VALIDATED_LOCALLY = "validated_locally"
    VERIFIED = "verified"
    PLANNED = "planned"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"
