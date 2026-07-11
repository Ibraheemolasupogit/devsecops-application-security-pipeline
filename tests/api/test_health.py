from fastapi.testclient import TestClient


def test_health_response(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "genomic-research-access-api",
        "version": "0.1.0",
    }
