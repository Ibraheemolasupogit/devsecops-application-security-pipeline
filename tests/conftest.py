from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from genomic_research_access_api.main import create_app


class DeterministicIds:
    def __init__(self) -> None:
        self._counter = 0

    def __call__(self) -> str:
        self._counter += 1
        return f"test-id-{self._counter:04d}"


class DeterministicClock:
    def __init__(self) -> None:
        self._current = datetime(2026, 1, 2, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        value = self._current
        self._current += timedelta(seconds=1)
        return value


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = create_app(clock=DeterministicClock(), id_factory=DeterministicIds())
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


@pytest.fixture
def access_request_payload() -> dict[str, str]:
    return {
        "dataset_id": "syn-rare-disease-001",
        "requester_id": "researcher-001",
        "research_purpose": "Evaluate aggregate rare disease cohort characteristics.",
        "requested_access_level": "aggregate_analysis",
    }
