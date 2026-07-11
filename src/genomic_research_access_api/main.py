"""FastAPI application factory."""

from collections.abc import Callable
from typing import cast
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import RequestResponseEndpoint

from genomic_research_access_api.api.router import api_router
from genomic_research_access_api.audit.service import AuditService
from genomic_research_access_api.config import get_settings
from genomic_research_access_api.data.seed import synthetic_datasets
from genomic_research_access_api.domain.clock import Clock, system_clock
from genomic_research_access_api.exceptions.app import ApplicationError
from genomic_research_access_api.exceptions.handlers import (
    application_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from genomic_research_access_api.logging.config import configure_logging
from genomic_research_access_api.repositories.access_requests import AccessRequestRepository
from genomic_research_access_api.repositories.audit_events import AuditEventRepository
from genomic_research_access_api.repositories.datasets import DatasetRepository
from genomic_research_access_api.services.access_requests import AccessRequestService
from genomic_research_access_api.services.datasets import DatasetService
from genomic_research_access_api.version import __version__


def create_app(
    *,
    clock: Clock = system_clock,
    id_factory: Callable[[], str] | None = None,
) -> FastAPI:
    configure_logging()
    settings = get_settings()
    make_id = id_factory or (lambda: str(uuid4()))
    app = FastAPI(
        title="Genomic Research Access API",
        version=__version__,
        description=(
            "Synthetic, non-identifiable portfolio API for controlled genomic research "
            "dataset access workflows."
        ),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin).rstrip("/") for origin in settings.cors_allowed_origins],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
        expose_headers=["X-Correlation-ID"],
    )

    @app.middleware("http")
    async def correlation_id_middleware(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    dataset_repository = DatasetRepository(synthetic_datasets())
    access_request_repository = AccessRequestRepository()
    audit_event_repository = AuditEventRepository()
    audit_service = AuditService(audit_event_repository, clock, make_id)
    app.state.audit_service = audit_service
    app.state.dataset_service = DatasetService(dataset_repository, audit_service)
    app.state.access_request_service = AccessRequestService(
        access_request_repository=access_request_repository,
        dataset_repository=dataset_repository,
        audit_service=audit_service,
        clock=clock,
        id_factory=make_id,
    )

    app.add_exception_handler(
        ApplicationError,
        cast(Callable[[Request, Exception], Response], application_error_handler),
    )
    app.add_exception_handler(
        RequestValidationError,
        cast(Callable[[Request, Exception], Response], validation_error_handler),
    )
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(api_router)
    return app


app = create_app()
