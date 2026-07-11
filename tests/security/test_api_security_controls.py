from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from fastapi.testclient import TestClient

from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.security.authentication.dev_tokens import issue_dev_token

PRIVATE_KEY = Path("tests/fixtures/keys/dev_private_key.pem").read_text(encoding="utf-8")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def custom_token(claim_overrides: dict[str, Any], *, algorithm: str = "RS256") -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": "https://local.dev/genomic-research-access-api",
        "aud": "genomic-research-access-api",
        "sub": "researcher-001",
        "name": "Researcher One",
        "roles": ["researcher"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "custom-token",
    }
    claims.update(claim_overrides)
    key = PRIVATE_KEY if algorithm == "RS256" else "not-the-rsa-key"
    return jwt.encode(claims, key, algorithm=algorithm)


def create_request(
    client: TestClient,
    headers: dict[str, str],
    *,
    dataset_id: str = "syn-rare-disease-001",
) -> str:
    response = client.post(
        "/api/v1/access-requests",
        json={
            "dataset_id": dataset_id,
            "research_purpose": "A controlled synthetic research purpose.",
            "requested_access_level": "aggregate_analysis"
            if dataset_id != "syn-cancer-001"
            else "controlled_export",
        },
        headers=headers,
    )
    assert response.status_code == 201
    return str(response.json()["request_id"])


def test_protected_route_requires_token(client: TestClient) -> None:
    response = client.get("/api/v1/datasets")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_valid_token_allows_researcher_action(
    client: TestClient, researcher_headers: dict[str, str]
) -> None:
    response = client.get("/api/v1/datasets", headers=researcher_headers)

    assert response.status_code == 200


def test_expired_token_rejected(client: TestClient) -> None:
    token = issue_dev_token(
        subject="researcher-001",
        issued_at=datetime.now(UTC) - timedelta(hours=1),
        expires_in_seconds=1,
    )

    response = client.get("/api/v1/datasets", headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "ACCESS_TOKEN_EXPIRED"


def test_future_not_before_token_rejected(client: TestClient) -> None:
    token = issue_dev_token(
        subject="researcher-001",
        not_before=datetime.now(UTC) + timedelta(hours=1),
    )

    response = client.get("/api/v1/datasets", headers=bearer(token))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "INVALID_ACCESS_TOKEN"


def test_clock_skew_boundary_token_allowed(client: TestClient) -> None:
    token = issue_dev_token(
        subject="researcher-001",
        issued_at=datetime.now(UTC),
        not_before=datetime.now(UTC) + timedelta(seconds=20),
        expires_in_seconds=300,
    )

    response = client.get("/api/v1/datasets", headers=bearer(token))

    assert response.status_code == 200


def test_wrong_issuer_and_audience_rejected(client: TestClient) -> None:
    issuer_response = client.get(
        "/api/v1/datasets", headers=bearer(custom_token({"iss": "wrong-issuer"}))
    )
    audience_response = client.get(
        "/api/v1/datasets", headers=bearer(custom_token({"aud": "wrong-audience"}))
    )

    assert issuer_response.json()["error"]["code"] == "INVALID_TOKEN_ISSUER"
    assert audience_response.json()["error"]["code"] == "INVALID_TOKEN_AUDIENCE"


def test_invalid_signature_unsupported_algorithm_and_malformed_token_rejected(
    client: TestClient,
) -> None:
    valid = issue_dev_token(subject="researcher-001")
    header, payload, signature = valid.split(".")
    invalid_signature = ".".join((header, payload, "A" * len(signature)))
    unsupported_algorithm = custom_token({}, algorithm="HS256")
    none_algorithm = jwt.encode(
        {
            "iss": "https://local.dev/genomic-research-access-api",
            "aud": "genomic-research-access-api",
            "sub": "researcher-001",
            "roles": ["researcher"],
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
            "jti": "none-token",
        },
        key="",
        algorithm="none",
    )

    responses = [
        client.get("/api/v1/datasets", headers=bearer(invalid_signature)),
        client.get("/api/v1/datasets", headers=bearer(unsupported_algorithm)),
        client.get("/api/v1/datasets", headers=bearer(none_algorithm)),
        client.get("/api/v1/datasets", headers=bearer("not-a-jwt")),
    ]

    assert [response.status_code for response in responses] == [401, 401, 401, 401]
    assert all(response.json()["error"]["code"] == "INVALID_ACCESS_TOKEN" for response in responses)


def test_missing_subject_missing_roles_and_unknown_role_rejected(client: TestClient) -> None:
    responses = [
        client.get("/api/v1/datasets", headers=bearer(custom_token({"sub": ""}))),
        client.get("/api/v1/datasets", headers=bearer(custom_token({"roles": []}))),
        client.get("/api/v1/datasets", headers=bearer(custom_token({"roles": ["superuser"]}))),
    ]

    assert [response.status_code for response in responses] == [401, 401, 401]


def test_multiple_roles_are_union_of_permissions(client: TestClient) -> None:
    token = issue_dev_token(
        subject="multi-role-001",
        roles=(ActorRole.RESEARCHER, ActorRole.APPROVER),
    )

    list_response = client.get("/api/v1/datasets", headers=bearer(token))
    approve_response = client.post(
        "/api/v1/access-requests/missing/approve",
        json={"decision_reason": "Review attempted."},
        headers=bearer(token),
    )

    assert list_response.status_code == 200
    assert approve_response.status_code == 404


def test_researcher_denied_approval_and_auditor_denied_approval(
    client: TestClient,
    researcher_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    request_id = create_request(client, researcher_headers)

    researcher_response = client.post(
        f"/api/v1/access-requests/{request_id}/approve",
        json={"decision_reason": "Trying to approve."},
        headers=researcher_headers,
    )
    auditor_response = client.post(
        f"/api/v1/access-requests/{request_id}/approve",
        json={"decision_reason": "Trying to approve."},
        headers=auditor_headers,
    )

    assert researcher_response.status_code == 403
    assert auditor_response.status_code == 403


def test_approver_denied_audit_and_auditor_permitted_audit(
    client: TestClient,
    approver_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    denied = client.get("/api/v1/audit-events", headers=approver_headers)
    allowed = client.get("/api/v1/audit-events", headers=auditor_headers)

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_researcher_reads_only_own_request(
    client: TestClient,
    researcher_headers: dict[str, str],
    researcher_two_headers: dict[str, str],
) -> None:
    own_id = create_request(client, researcher_headers)
    other_id = create_request(client, researcher_two_headers)

    own_response = client.get(f"/api/v1/access-requests/{own_id}", headers=researcher_headers)
    denied_response = client.get(f"/api/v1/access-requests/{other_id}", headers=researcher_headers)
    list_response = client.get("/api/v1/access-requests", headers=researcher_headers)

    assert own_response.status_code == 200
    assert denied_response.status_code == 404
    assert [item["request_id"] for item in list_response.json()] == [own_id]


def test_approver_can_read_reviewable_request(
    client: TestClient,
    researcher_headers: dict[str, str],
    approver_headers: dict[str, str],
) -> None:
    request_id = create_request(client, researcher_headers)

    response = client.get(f"/api/v1/access-requests/{request_id}", headers=approver_headers)

    assert response.status_code == 200
    assert response.json()["request_id"] == request_id


def test_restricted_dataset_requires_entitlement_then_allows_after_approval(
    client: TestClient,
    researcher_headers: dict[str, str],
    approver_headers: dict[str, str],
) -> None:
    denied = client.get("/api/v1/datasets/syn-cancer-001", headers=researcher_headers)

    request_id = create_request(client, researcher_headers, dataset_id="syn-cancer-001")
    approval = client.post(
        f"/api/v1/access-requests/{request_id}/approve",
        json={"decision_reason": "Approved restricted metadata access."},
        headers=approver_headers,
    )
    allowed = client.get("/api/v1/datasets/syn-cancer-001", headers=researcher_headers)

    assert denied.status_code == 404
    assert approval.status_code == 200
    assert allowed.status_code == 200


def test_requester_and_admin_cannot_approve_own_request(
    client: TestClient,
    researcher_headers: dict[str, str],
    admin_headers: dict[str, str],
) -> None:
    researcher_request = create_request(client, researcher_headers)
    admin_request = create_request(client, admin_headers)

    researcher_response = client.post(
        f"/api/v1/access-requests/{researcher_request}/approve",
        json={"decision_reason": "Self approval."},
        headers=researcher_headers,
    )
    admin_response = client.post(
        f"/api/v1/access-requests/{admin_request}/approve",
        json={"decision_reason": "Admin self approval."},
        headers=admin_headers,
    )
    admin_reject_response = client.post(
        f"/api/v1/access-requests/{admin_request}/reject",
        json={"decision_reason": "Admin self rejection."},
        headers=admin_headers,
    )

    assert researcher_response.status_code == 403
    assert admin_response.status_code == 403
    assert admin_reject_response.status_code == 403
    assert researcher_response.json()["error"]["code"] in {
        "INSUFFICIENT_PERMISSION",
        "SEPARATION_OF_DUTIES_VIOLATION",
    }
    assert admin_response.json()["error"]["code"] == "SEPARATION_OF_DUTIES_VIOLATION"
    assert admin_reject_response.json()["error"]["code"] == "SEPARATION_OF_DUTIES_VIOLATION"


def test_application_admin_can_read_audit_events(
    client: TestClient,
    admin_headers: dict[str, str],
) -> None:
    response = client.get("/api/v1/audit-events", headers=admin_headers)

    assert response.status_code == 200


def test_mass_assignment_fields_are_rejected(
    client: TestClient, researcher_headers: dict[str, str]
) -> None:
    payload = {
        "dataset_id": "syn-rare-disease-001",
        "research_purpose": "Valid purpose.",
        "requested_access_level": "aggregate_analysis",
        "requester_id": "attacker",
        "status": "approved",
        "reviewed_by": "attacker",
        "submitted_at": "2026-01-01T00:00:00Z",
    }

    response = client.post("/api/v1/access-requests", json=payload, headers=researcher_headers)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_security_headers_cors_and_correlation_controls(
    client: TestClient, researcher_headers: dict[str, str]
) -> None:
    allowed = client.options(
        "/api/v1/datasets",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "GET",
        },
    )
    disallowed = client.options(
        "/api/v1/datasets",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    response = client.get(
        "/api/v1/datasets",
        headers=researcher_headers | {"X-Correlation-ID": "bad\nid"},
    )

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:8000"
    assert "access-control-allow-origin" not in disallowed.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Correlation-ID"] != "bad\nid"


def test_auth_failure_and_denial_are_audited_without_raw_token(
    client: TestClient,
    auditor_headers: dict[str, str],
    researcher_headers: dict[str, str],
) -> None:
    raw_token = "not-a-jwt"
    client.get("/api/v1/datasets", headers=bearer(raw_token))
    client.get("/api/v1/audit-events", headers=researcher_headers)

    events = client.get("/api/v1/audit-events", headers=auditor_headers).json()
    serialized = str(events)

    assert any(event["event_type"] == "authentication_failed" for event in events)
    assert any(event["event_type"] == "authorisation_denied" for event in events)
    assert raw_token not in serialized
