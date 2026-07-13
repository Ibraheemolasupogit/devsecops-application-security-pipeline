"""Controlled vocabularies for canonical product-security findings."""

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class FindingType(StrEnum):
    THREAT_MODEL = "Threat Model"
    SAST = "SAST"
    SCA = "SCA"
    SECRET = "Secret"
    IAC = "IaC"
    CONTAINER = "Container"
    DAST = "DAST"
    API_SECURITY = "API Security"
    AUTHENTICATION = "Authentication"
    AUTHORISATION = "Authorisation"
    OBJECT_LEVEL_AUTHORISATION = "Object-Level Authorisation"
    SECURE_DESIGN = "Secure Design"
    CONFIGURATION = "Configuration"
    SUPPLY_CHAIN = "Supply Chain"


class SourceType(StrEnum):
    THREAT_MODEL = "threat_model"
    STATIC_ANALYSIS = "static_analysis"
    DEPENDENCY_SCAN = "dependency_scan"
    SECRET_SCAN = "secret_scan"
    IAC_SCAN = "iac_scan"
    CONTAINER_SCAN = "container_scan"
    DYNAMIC_SCAN = "dynamic_scan"
    TEST_RESULT = "test_result"
    MANUAL_FIXTURE = "manual_fixture"


class FindingStatus(StrEnum):
    ACTIVE = "active"
    SUPPRESSED = "suppressed"
    INFORMATIONAL = "informational"
    PASSED_CONTROL = "passed_control"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    P5 = "P5"
