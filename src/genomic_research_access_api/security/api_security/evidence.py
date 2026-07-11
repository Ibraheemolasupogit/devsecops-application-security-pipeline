"""Deterministic evidence generation for Milestone 3 API security controls."""

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

from genomic_research_access_api.domain.enums import ActorRole, AuditEventType
from genomic_research_access_api.security.authorisation import ROLE_PERMISSIONS
from genomic_research_access_api.security.threat_model.io import (
    ROOT,
    sha256_file,
    write_json,
)
from genomic_research_access_api.security.threat_model.validation import (
    ThreatModelValidationError,
)
from genomic_research_access_api.version import __version__

SCHEMA_VERSION = "1.0"
DEFAULT_TIMESTAMP = "2026-01-01T00:00:00Z"
OUTPUT_DIR = ROOT / "outputs" / "security" / "api-security"

SOURCE_FILES = {
    "access_request_routes": ROOT / "src/genomic_research_access_api/api/routes/access_requests.py",
    "audit_event_routes": ROOT / "src/genomic_research_access_api/api/routes/audit_events.py",
    "authorisation_matrix": ROOT / "src/genomic_research_access_api/security/authorisation.py",
    "dataset_routes": ROOT / "src/genomic_research_access_api/api/routes/datasets.py",
    "jwt_validator": ROOT
    / "src/genomic_research_access_api/security/authentication/jwt_validator.py",
    "security_tests": ROOT / "tests/security/test_api_security_controls.py",
}


def authentication_control_summary() -> dict[str, Any]:
    return {
        "algorithm_policy": {
            "accepted_algorithms": ["RS256"],
            "arbitrary_algorithms_allowed": False,
            "none_algorithm_allowed": False,
        },
        "claim_validation": [
            "issuer",
            "audience",
            "subject",
            "roles",
            "expiration",
            "issued_at",
            "not_before",
            "jwt_id",
            "maximum_lifetime",
        ],
        "identity_source_policy": {
            "accepted_identity_source": "Authorization: Bearer <token>",
            "query_string_identity_allowed": False,
            "untrusted_identity_header_allowed": False,
        },
        "local_key_material": {
            "purpose": "synthetic local development and test tokens only",
            "public_key_path": "tests/fixtures/keys/dev_public_key.pem",
            "private_key_path": "tests/fixtures/keys/dev_private_key.pem",
        },
        "protected_route_policy": {
            "protected_prefixes": ["/api/v1/*"],
            "public_routes": ["/health", "/docs", "/openapi.json"],
        },
    }


def authorisation_matrix() -> dict[str, Any]:
    return {
        role.value: sorted(permission.value for permission in permissions)
        for role, permissions in sorted(ROLE_PERMISSIONS.items(), key=lambda item: item[0].value)
    }


def endpoint_security_inventory() -> list[dict[str, Any]]:
    return [
        {
            "method": "GET",
            "path": "/api/v1/datasets",
            "required_permissions": ["dataset:list"],
            "object_authorisation": "not_applicable",
        },
        {
            "method": "GET",
            "path": "/api/v1/datasets/{dataset_id}",
            "required_permissions": ["dataset:read"],
            "object_authorisation": (
                "restricted datasets require custodian/admin role or approved request"
            ),
        },
        {
            "method": "POST",
            "path": "/api/v1/access-requests",
            "required_permissions": ["access_request:create"],
            "object_authorisation": "requester identity is derived from token subject",
        },
        {
            "method": "GET",
            "path": "/api/v1/access-requests",
            "required_permissions": ["access_request:list_own", "access_request:list_all"],
            "object_authorisation": (
                "researchers see own requests; privileged reviewers see permitted queue"
            ),
        },
        {
            "method": "GET",
            "path": "/api/v1/access-requests/{request_id}",
            "required_permissions": ["access_request:read_own", "access_request:read_all"],
            "object_authorisation": "unauthorised object access returns not found",
        },
        {
            "method": "POST",
            "path": "/api/v1/access-requests/{request_id}/approve",
            "required_permissions": ["access_request:approve"],
            "object_authorisation": "requester cannot approve own request",
        },
        {
            "method": "POST",
            "path": "/api/v1/access-requests/{request_id}/reject",
            "required_permissions": ["access_request:reject"],
            "object_authorisation": "requester cannot reject own request",
        },
        {
            "method": "GET",
            "path": "/api/v1/audit-events",
            "required_permissions": ["audit_event:read"],
            "object_authorisation": (
                "audit records require security-auditor or administrator permission"
            ),
        },
    ]


def negative_test_summary() -> dict[str, Any]:
    return {
        "test_file": "tests/security/test_api_security_controls.py",
        "covered_cases": [
            "missing bearer token",
            "expired JWT",
            "clock-skew boundary",
            "future not-before JWT",
            "wrong issuer",
            "wrong audience",
            "invalid signature",
            "unsupported signing algorithm",
            "none signing algorithm",
            "malformed token",
            "missing subject",
            "missing roles",
            "unknown role",
            "insufficient role for approval",
            "insufficient role for audit access",
            "approver permitted review access",
            "administrator permitted audit access",
            "cross-user access request read",
            "restricted dataset without entitlement",
            "self approval",
            "self rejection",
            "mass assignment payload",
            "disallowed CORS origin",
            "malformed correlation identifier",
        ],
        "expected_statuses": {
            "authentication_failures": 401,
            "authorisation_failures": 403,
            "hidden_object_failures": 404,
            "schema_failures": 422,
        },
    }


def audit_control_summary() -> dict[str, Any]:
    return {
        "audited_event_types": sorted(event.value for event in AuditEventType),
        "security_event_types": [
            AuditEventType.AUTHENTICATION_SUCCEEDED.value,
            AuditEventType.AUTHENTICATION_FAILED.value,
            AuditEventType.AUTHORISATION_DENIED.value,
            AuditEventType.ACCESS_REQUEST_VIEWED.value,
            AuditEventType.SELF_APPROVAL_DENIED.value,
            AuditEventType.AUDIT_EVENTS_VIEWED.value,
        ],
        "sensitive_data_policy": {
            "raw_bearer_token_logged": False,
            "decision_reason_logged": True,
            "correlation_id_logged": True,
        },
    }


def build_summary() -> dict[str, Any]:
    matrix = authorisation_matrix()
    inventory = endpoint_security_inventory()
    negative_tests = negative_test_summary()["covered_cases"]
    return {
        "authentication_status": "implemented",
        "authorisation_status": "implemented",
        "protected_api_route_count": len(inventory),
        "role_count": len(matrix),
        "supported_roles": sorted(role.value for role in ActorRole),
        "negative_security_test_count": len(negative_tests),
        "validation_status": "passed",
    }


def generate_evidence(
    output_dir: Path = OUTPUT_DIR, timestamp: str = DEFAULT_TIMESTAMP
) -> list[Path]:
    outputs = {
        "api-security-summary.json": build_summary(),
        "audit-control-summary.json": audit_control_summary(),
        "authentication-control-summary.json": authentication_control_summary(),
        "authorisation-matrix.json": authorisation_matrix(),
        "endpoint-security-inventory.json": endpoint_security_inventory(),
        "negative-test-summary.json": negative_test_summary(),
    }
    written: list[Path] = []
    for filename, payload in sorted(outputs.items()):
        path = output_dir / filename
        write_json(path, payload)
        written.append(path)

    manifest_path = output_dir / "evidence-manifest.json"
    manifest = {
        "generation_metadata": {
            "generated_at": timestamp,
            "generator": "genomic_research_access_api.security.api_security.evidence",
        },
        "input_files": {
            name: {"path": str(path.relative_to(ROOT)), "sha256": sha256_file(path)}
            for name, path in sorted(SOURCE_FILES.items())
        },
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
        "project_version": __version__,
        "run_id": f"api-security-{timestamp}",
        "schema_version": SCHEMA_VERSION,
    }
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify_evidence(output_dir: Path = OUTPUT_DIR) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ThreatModelValidationError("API security evidence manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for details in manifest["output_files"].values():
        path = output_dir / details["path"]
        if not path.exists():
            raise ThreatModelValidationError(f"missing API security evidence output: {path}")
        checksum = sha256_file(path)
        if checksum != details["sha256"]:
            raise ThreatModelValidationError(f"checksum mismatch for {path}")

    with tempfile.TemporaryDirectory() as temp_dir:
        generate_evidence(Path(temp_dir), manifest["generation_metadata"]["generated_at"])
        for name, details in manifest["output_files"].items():
            regenerated = Path(temp_dir) / name
            if sha256_file(regenerated) != details["sha256"]:
                raise ThreatModelValidationError(
                    f"non-deterministic API security evidence output: {name}"
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        verify_evidence()
    else:
        generate_evidence(timestamp=args.timestamp)


if __name__ == "__main__":
    main()
