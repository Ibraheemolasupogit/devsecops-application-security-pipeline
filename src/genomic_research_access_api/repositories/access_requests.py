"""In-memory access request repository."""

from genomic_research_access_api.domain.models import AccessRequest


class AccessRequestRepository:
    def __init__(self) -> None:
        self._requests: dict[str, AccessRequest] = {}

    def add(self, access_request: AccessRequest) -> AccessRequest:
        self._requests[access_request.request_id] = access_request
        return access_request

    def list(self) -> list[AccessRequest]:
        return sorted(self._requests.values(), key=lambda request: request.submitted_at)

    def get(self, request_id: str) -> AccessRequest | None:
        return self._requests.get(request_id)

    def update(self, access_request: AccessRequest) -> AccessRequest:
        self._requests[access_request.request_id] = access_request
        return access_request
