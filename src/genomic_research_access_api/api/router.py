"""Application API router."""

from fastapi import APIRouter

from genomic_research_access_api.api.routes import access_requests, audit_events, datasets, health

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(datasets.router)
api_router.include_router(access_requests.router)
api_router.include_router(audit_events.router)
