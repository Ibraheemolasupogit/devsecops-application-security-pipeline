"""Local demonstration audit event route."""

from fastapi import APIRouter, Request

from genomic_research_access_api.schemas.audit import AuditEventResponse

router = APIRouter(prefix="/api/v1/audit-events", tags=["audit events"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(request: Request) -> list[AuditEventResponse]:
    """Return local in-memory audit events for Milestone 1 demonstration only."""

    return [
        AuditEventResponse.model_validate(event, from_attributes=True)
        for event in request.app.state.audit_service.list_events()
    ]
