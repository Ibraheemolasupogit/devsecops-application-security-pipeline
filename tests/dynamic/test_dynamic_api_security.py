from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import jwt
import pytest
from fastapi.testclient import TestClient

from genomic_research_access_api.config import get_settings
from genomic_research_access_api.domain.enums import ActorRole
from genomic_research_access_api.main import create_app
from genomic_research_access_api.security.authentication.dev_tokens import issue_dev_token
from genomic_research_access_api.security.rate_limit import InMemoryRateLimiter

PRIVATE_KEY = Path("tests/fixtures/keys/dev_private_key.pem").read_text(encoding="utf-8")


class DynamicIds:
    def __init__(self) -> None:
        self._counter = 0

    def __call__(self) -> str:
        self._counter += 1
        return f"dynamic-id-{self._counter:04d}"


class DynamicClock:
    def __init__(self) -> None:
        self._current = datetime(2026, 1, 3, 9, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        value = self._current
        self._current += timedelta(seconds=1)
        return value


def token(subject: str, *, roles: tuple[ActorRole, ...] | None = None) -> str:
    return issue_dev_token(subject=subject, roles=roles, token_id=f"dynamic-{subject}")


def bearer(raw_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw_token}"}


def headers(subject: str, *, roles: tuple[ActorRole, ...] | None = None) -> dict[str, str]:
    return bearer(token(subject, roles=roles))


def custom_token(overrides: dict[str, Any], *, algorithm: str = "RS256") -> str:
    settings = get_settings()
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": "researcher-001",
        "name": "Researcher One",
        "roles": ["researcher"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "jti": "dynamic-custom-token",
    }
    claims.update(overrides)
    key = PRIVATE_KEY if algorithm == "RS256" else "not-the-rsa-key"
    return jwt.encode(claims, key, algorithm=algorithm)


@pytest.fixture
def dynamic_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    get_settings.cache_clear()
    monkeypatch.setenv("GRAA_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("GRAA_RATE_LIMIT_REQUESTS", "50")
    monkeypatch.setenv("GRAA_RATE_LIMIT_WINDOW_SECONDS", "60")
    app = create_app(clock=DynamicClock(), id_factory=DynamicIds())
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
    get_settings.cache_clear()


def create_request(
    client: TestClient,
    request_headers: dict[str, str],
    *,
    dataset_id: str = "syn-rare-disease-001",
) -> str:
    response = client.post(
        "/api/v1/access-requests",
        headers=request_headers,
        json={
            "dataset_id": dataset_id,
            "research_purpose": "Synthetic dynamic security validation.",
            "requested_access_level": "aggregate_analysis"
            if dataset_id != "syn-cancer-001"
            else "controlled_export",
        },
    )
    assert response.status_code == 201
    return str(response.json()["request_id"])


@pytest.mark.dynamic_category("authentication")
def test_authentication_boundary_failures(dynamic_client: TestClient) -> None:
    cases = [
        ("missing", {}),
        ("malformed", bearer("not-a-jwt")),
        (
            "invalid_signature",
            bearer(".".join([*token("researcher-001").split(".")[:2], "bad"])),
        ),
        (
            "expired",
            bearer(
                issue_dev_token(
                    subject="researcher-001",
                    issued_at=datetime.now(UTC) - timedelta(hours=1),
                    expires_in_seconds=1,
                )
            ),
        ),
        (
            "future_nbf",
            bearer(
                issue_dev_token(
                    subject="researcher-001",
                    not_before=datetime.now(UTC) + timedelta(hours=1),
                )
            ),
        ),
        ("wrong_issuer", bearer(custom_token({"iss": "wrong"}))),
        ("wrong_audience", bearer(custom_token({"aud": "wrong"}))),
        ("missing_subject", bearer(custom_token({"sub": ""}))),
        ("missing_role", bearer(custom_token({"roles": []}))),
        ("unknown_role", bearer(custom_token({"roles": ["superuser"]}))),
        ("unsupported_algorithm", bearer(custom_token({}, algorithm="HS256"))),
        (
            "none_algorithm",
            bearer(
                jwt.encode(
                    {
                        "iss": get_settings().jwt_issuer,
                        "aud": get_settings().jwt_audience,
                        "sub": "researcher-001",
                        "roles": ["researcher"],
                        "iat": int(datetime.now(UTC).timestamp()),
                        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
                        "jti": "none-token",
                    },
                    key="",
                    algorithm="none",
                )
            ),
        ),
    ]
    for _, request_headers in cases:
        response = dynamic_client.get("/api/v1/datasets", headers=request_headers)
        assert response.status_code == 401
        assert "Traceback" not in response.text
        assert "not-a-jwt" not in response.text
        assert response.headers.get("WWW-Authenticate", "").startswith("Bearer")


@pytest.mark.dynamic_category("authorisation")
def test_authorisation_role_matrix(dynamic_client: TestClient) -> None:
    request_id = create_request(dynamic_client, headers("researcher-001"))
    cases = [
        (
            "researcher_approve",
            headers("researcher-001"),
            "post",
            f"/api/v1/access-requests/{request_id}/approve",
            403,
        ),
        (
            "researcher_reject",
            headers("researcher-001"),
            "post",
            f"/api/v1/access-requests/{request_id}/reject",
            403,
        ),
        ("researcher_audit", headers("researcher-001"), "get", "/api/v1/audit-events", 403),
        ("approver_audit", headers("approver-001"), "get", "/api/v1/audit-events", 403),
        (
            "auditor_approve",
            headers("auditor-001"),
            "post",
            f"/api/v1/access-requests/{request_id}/approve",
            403,
        ),
        (
            "auditor_reject",
            headers("auditor-001"),
            "post",
            f"/api/v1/access-requests/{request_id}/reject",
            403,
        ),
    ]
    for _, request_headers, method, path, expected in cases:
        payload = {"decision_reason": "Dynamic boundary attempt."}
        if method == "post":
            response = dynamic_client.post(path, headers=request_headers, json=payload)
        else:
            response = dynamic_client.get(path, headers=request_headers)
        assert response.status_code == expected


@pytest.mark.dynamic_category("object_access")
def test_object_level_access_boundaries(dynamic_client: TestClient) -> None:
    own_id = create_request(dynamic_client, headers("researcher-001"))
    other_id = create_request(dynamic_client, headers("researcher-002"))
    own = dynamic_client.get(f"/api/v1/access-requests/{own_id}", headers=headers("researcher-001"))
    other = dynamic_client.get(
        f"/api/v1/access-requests/{other_id}", headers=headers("researcher-001")
    )
    missing = dynamic_client.get(
        "/api/v1/access-requests/not-a-real-id", headers=headers("researcher-001")
    )
    listed = dynamic_client.get("/api/v1/access-requests", headers=headers("researcher-001"))
    restricted_before = dynamic_client.get(
        "/api/v1/datasets/syn-cancer-001", headers=headers("researcher-001")
    )
    restricted_request_id = create_request(
        dynamic_client, headers("researcher-001"), dataset_id="syn-cancer-001"
    )
    approval = dynamic_client.post(
        f"/api/v1/access-requests/{restricted_request_id}/approve",
        headers=headers("approver-001"),
        json={"decision_reason": "Dynamic restricted dataset approval."},
    )
    restricted_after = dynamic_client.get(
        "/api/v1/datasets/syn-cancer-001", headers=headers("researcher-001")
    )
    assert own.status_code == 200
    assert other.status_code == 404
    assert missing.status_code == 404
    assert [item["request_id"] for item in listed.json()] == [own_id]
    assert restricted_before.status_code == 404
    assert approval.status_code == 200
    assert restricted_after.status_code == 200


@pytest.mark.dynamic_category("input_mutation")
def test_input_mutation_and_malformed_payloads(dynamic_client: TestClient) -> None:
    mutated_payloads: list[object] = [
        {},
        {"dataset_id": "", "research_purpose": "x", "requested_access_level": "aggregate_analysis"},
        {
            "dataset_id": "syn-rare-disease-001",
            "research_purpose": " ",
            "requested_access_level": "aggregate_analysis",
        },
        {"dataset_id": 123, "research_purpose": [], "requested_access_level": "invalid"},
        {
            "dataset_id": "syn-rare-disease-001",
            "research_purpose": "x" * 5000,
            "requested_access_level": "aggregate_analysis",
        },
        {
            "dataset_id": "syn-rare-disease-001",
            "research_purpose": "x",
            "requested_access_level": "aggregate_analysis",
            "status": "approved",
        },
        [],
        None,
    ]
    for payload in mutated_payloads:
        response = dynamic_client.post(
            "/api/v1/access-requests", headers=headers("researcher-001"), json=payload
        )
        assert response.status_code in {400, 422}
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"
        assert "Traceback" not in response.text
    malformed = dynamic_client.post(
        "/api/v1/access-requests",
        headers=headers("researcher-001") | {"Content-Type": "application/json"},
        content='{"dataset_id": "syn-rare-disease-001",',
    )
    wrong_type = dynamic_client.post(
        "/api/v1/access-requests",
        headers=headers("researcher-001") | {"Content-Type": "text/plain"},
        content="not json",
    )
    assert malformed.status_code == 422
    assert wrong_type.status_code == 422


@pytest.mark.dynamic_category("security_headers")
def test_security_headers_on_representative_responses(dynamic_client: TestClient) -> None:
    responses = [
        dynamic_client.get("/health"),
        dynamic_client.get("/api/v1/datasets", headers=headers("researcher-001")),
        dynamic_client.get("/api/v1/datasets"),
        dynamic_client.get("/api/v1/audit-events", headers=headers("researcher-001")),
        dynamic_client.get("/api/v1/unknown", headers=headers("researcher-001")),
    ]
    for response in responses:
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "X-Correlation-ID" in response.headers
        assert "Strict-Transport-Security" not in response.headers
    assert responses[1].headers["Cache-Control"] == "no-store"


@pytest.mark.dynamic_category("cors")
def test_cors_controls(dynamic_client: TestClient) -> None:
    allowed = dynamic_client.options(
        "/api/v1/datasets",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        },
    )
    disallowed_origin = dynamic_client.options(
        "/api/v1/datasets",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    disallowed_method = dynamic_client.options(
        "/api/v1/datasets",
        headers={
            "Origin": "http://localhost:8000",
            "Access-Control-Request-Method": "DELETE",
        },
    )
    null_origin = dynamic_client.options(
        "/api/v1/datasets",
        headers={"Origin": "null", "Access-Control-Request-Method": "GET"},
    )
    assert allowed.status_code == 200
    assert allowed.headers["access-control-allow-origin"] == "http://localhost:8000"
    assert "access-control-allow-credentials" not in allowed.headers
    assert "access-control-allow-origin" not in disallowed_origin.headers
    assert disallowed_method.status_code == 400
    assert "access-control-allow-origin" not in null_origin.headers


@pytest.mark.dynamic_category("resource_consumption")
def test_rate_limit_behaviour(dynamic_client: TestClient) -> None:
    cast(Any, dynamic_client.app).state.rate_limiter = InMemoryRateLimiter(
        max_requests=6, window_seconds=60, max_subjects=32
    )
    first_subject = headers("researcher-001")
    second_subject = headers("researcher-002")
    for _ in range(6):
        assert dynamic_client.get("/api/v1/datasets", headers=first_subject).status_code == 200
    limited = dynamic_client.get("/api/v1/datasets", headers=first_subject)
    other_subject = dynamic_client.get("/api/v1/datasets", headers=second_subject)
    malformed_identity = dynamic_client.get(
        "/api/v1/datasets", headers={"Authorization": "Bearer malformed subject\nvalue"}
    )
    assert limited.status_code == 429
    assert limited.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in limited.headers
    assert other_subject.status_code == 200
    assert malformed_identity.status_code in {401, 429}


@pytest.mark.dynamic_category("audit")
def test_dynamic_audit_events(dynamic_client: TestClient) -> None:
    dynamic_client.get("/api/v1/datasets")
    request_id = create_request(dynamic_client, headers("researcher-001"))
    admin_request_id = create_request(dynamic_client, headers("admin-001"))
    dynamic_client.get(f"/api/v1/access-requests/{request_id}", headers=headers("researcher-002"))
    dynamic_client.post(
        f"/api/v1/access-requests/{admin_request_id}/approve",
        headers=headers("admin-001"),
        json={"decision_reason": "Self approval attempt."},
    )
    dynamic_client.post(
        f"/api/v1/access-requests/{request_id}/approve",
        headers=headers("approver-001"),
        json={"decision_reason": "Successful approval."},
    )
    dynamic_client.post(
        f"/api/v1/access-requests/{request_id}/reject",
        headers=headers("approver-001"),
        json={"decision_reason": "Invalid state transition."},
    )
    dynamic_client.get("/api/v1/audit-events", headers=headers("auditor-001"))
    events = dynamic_client.get("/api/v1/audit-events", headers=headers("auditor-001")).json()
    event_types = {event["event_type"] for event in events}
    assert {
        "authentication_failed",
        "authorisation_denied",
        "self_approval_denied",
        "access_request_approved",
        "invalid_workflow_transition_attempted",
        "audit_events_viewed",
    }.issubset(event_types)
    assert all(event["correlation_id"] for event in events)
    assert "eyJ" not in str(events)
