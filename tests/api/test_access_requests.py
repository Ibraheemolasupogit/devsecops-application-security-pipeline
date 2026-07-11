from typing import cast

from fastapi.testclient import TestClient


def create_request(
    client: TestClient, payload: dict[str, str], headers: dict[str, str]
) -> dict[str, object]:
    response = client.post(
        "/api/v1/access-requests",
        json=payload,
        headers=headers | {"X-Correlation-ID": "corr-new"},
    )
    assert response.status_code == 201
    return cast(dict[str, object], response.json())


def test_successful_access_request_creation(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    body = create_request(client, access_request_payload, researcher_headers)

    assert body["request_id"] == "test-id-0002"
    assert body["requester_id"] == "researcher-001"
    assert body["status"] == "pending"
    assert body["reviewed_at"] is None

    audit_response = client.get("/api/v1/audit-events", headers=auditor_headers)
    assert any(event["event_type"] == "access_request_submitted" for event in audit_response.json())


def test_invalid_dataset_in_access_request(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
) -> None:
    access_request_payload["dataset_id"] = "missing-dataset"

    response = client.post(
        "/api/v1/access-requests", json=access_request_payload, headers=researcher_headers
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "DATASET_NOT_FOUND"


def test_empty_research_purpose_rejected(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
) -> None:
    access_request_payload["research_purpose"] = "   "

    response = client.post(
        "/api/v1/access-requests", json=access_request_payload, headers=researcher_headers
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_request_retrieval(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
) -> None:
    created = create_request(client, access_request_payload, researcher_headers)

    response = client.get(
        f"/api/v1/access-requests/{created['request_id']}", headers=researcher_headers
    )

    assert response.status_code == 200
    assert response.json()["request_id"] == created["request_id"]


def test_successful_approval(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
    approver_headers: dict[str, str],
) -> None:
    created = create_request(client, access_request_payload, researcher_headers)

    response = client.post(
        f"/api/v1/access-requests/{created['request_id']}/approve",
        json={"decision_reason": "Approved for aggregate analysis in local demo."},
        headers=approver_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "approved"
    assert body["reviewed_by"] == "approver-001"
    assert body["decision_reason"] == "Approved for aggregate analysis in local demo."


def test_successful_rejection(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
    approver_headers: dict[str, str],
) -> None:
    created = create_request(client, access_request_payload, researcher_headers)

    response = client.post(
        f"/api/v1/access-requests/{created['request_id']}/reject",
        json={"decision_reason": "Purpose is too broad for this synthetic workflow."},
        headers=approver_headers,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"


def test_invalid_state_transition_records_audit_event(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
    approver_headers: dict[str, str],
    auditor_headers: dict[str, str],
) -> None:
    created = create_request(client, access_request_payload, researcher_headers)
    approve_path = f"/api/v1/access-requests/{created['request_id']}/approve"
    assert (
        client.post(
            approve_path,
            json={"decision_reason": "Initial approval."},
            headers=approver_headers,
        ).status_code
        == 200
    )

    response = client.post(
        approve_path,
        json={"decision_reason": "Second approval should fail."},
        headers=approver_headers | {"X-Correlation-ID": "corr-transition"},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INVALID_ACCESS_REQUEST_TRANSITION"
    events = client.get("/api/v1/audit-events", headers=auditor_headers).json()
    assert any(
        event["event_type"] == "invalid_workflow_transition_attempted"
        and event["outcome"] == "failure"
        and event["correlation_id"] == "corr-transition"
        for event in events
    )


def test_unknown_access_request(client: TestClient, researcher_headers: dict[str, str]) -> None:
    response = client.get("/api/v1/access-requests/missing", headers=researcher_headers)

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "ACCESS_REQUEST_NOT_FOUND"


def test_list_access_requests_stable_order(
    client: TestClient,
    access_request_payload: dict[str, str],
    researcher_headers: dict[str, str],
) -> None:
    first = create_request(client, access_request_payload, researcher_headers)
    second_payload = access_request_payload | {"research_purpose": "Second valid purpose."}
    second = create_request(client, second_payload, researcher_headers)

    response = client.get("/api/v1/access-requests", headers=researcher_headers)

    assert response.status_code == 200
    assert [item["request_id"] for item in response.json()] == [
        first["request_id"],
        second["request_id"],
    ]
