from fastapi.testclient import TestClient


def test_dataset_listing_is_stable_and_synthetic(
    client: TestClient, researcher_headers: dict[str, str]
) -> None:
    response = client.get("/api/v1/datasets", headers=researcher_headers)

    assert response.status_code == 200
    body = response.json()
    assert [dataset["dataset_id"] for dataset in body] == [
        "syn-cancer-001",
        "syn-pharmacogenomics-001",
        "syn-population-001",
        "syn-rare-disease-001",
    ]
    assert {dataset["research_domain"] for dataset in body} == {
        "rare disease research",
        "cancer research",
        "population genomics",
        "pharmacogenomics",
    }


def test_dataset_lookup_records_audit_event(
    client: TestClient, admin_headers: dict[str, str], auditor_headers: dict[str, str]
) -> None:
    response = client.get(
        "/api/v1/datasets/syn-cancer-001",
        headers=admin_headers | {"X-Correlation-ID": "corr-123"},
    )

    assert response.status_code == 200
    assert response.headers["X-Correlation-ID"] == "corr-123"
    assert response.json()["name"] == "Synthetic Oncology Variant Catalogue"

    audit_response = client.get("/api/v1/audit-events", headers=auditor_headers)
    assert audit_response.status_code == 200
    events = audit_response.json()
    assert any(
        event["event_type"] == "dataset_viewed" and event["correlation_id"] == "corr-123"
        for event in events
    )


def test_unknown_dataset_returns_structured_error(
    client: TestClient, researcher_headers: dict[str, str]
) -> None:
    response = client.get(
        "/api/v1/datasets/unknown",
        headers=researcher_headers | {"X-Correlation-ID": "corr-missing"},
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "DATASET_NOT_FOUND",
            "message": "The requested dataset was not found.",
            "correlation_id": "corr-missing",
        }
    }
