# Application Architecture

Milestone 1 implements a small FastAPI service named Genomic Research Access API. It uses deterministic synthetic data and in-memory repositories so the full application remains runnable locally with no AWS account or external service.

```mermaid
flowchart TB
    Client["HTTP client"] --> Middleware["Correlation ID middleware"]
    Middleware --> Router["FastAPI routers"]
    Router --> DatasetRoutes["Dataset routes"]
    Router --> RequestRoutes["Access request routes"]
    Router --> AuditRoutes["Local audit route"]
    DatasetRoutes --> DatasetService["DatasetService"]
    RequestRoutes --> RequestService["AccessRequestService"]
    DatasetService --> DatasetRepo["DatasetRepository"]
    RequestService --> RequestRepo["AccessRequestRepository"]
    RequestService --> DatasetRepo
    DatasetService --> AuditService["AuditService"]
    RequestService --> AuditService
    AuditService --> AuditRepo["AuditEventRepository"]
    DatasetRepo --> SeedData["Synthetic seed data"]
    Router --> Schemas["Pydantic v2 schemas"]
    Router --> Exceptions["Central exception handlers"]
```

## Boundaries

- Routes handle HTTP concerns only.
- Schemas handle request and response validation.
- Domain models and enums define controlled business concepts.
- Services enforce workflow behavior.
- Repositories encapsulate in-memory persistence.
- Audit handling records structured events without logging sensitive request content.
- Configuration keeps local secure defaults and avoids wildcard CORS.

## Extension Points

The repository and service boundaries are intentionally simple. Later milestones can replace in-memory persistence, add real identity, enforce object-level authorisation, and attach scanner or cloud controls without redesigning the Milestone 1 API foundation.
