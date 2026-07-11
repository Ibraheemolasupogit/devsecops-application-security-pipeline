# Milestone 1

Milestone 1 creates the repository foundation and secure reference application for future Product Security and DevSecOps work.

## Delivered

- FastAPI application called Genomic Research Access API.
- Deterministic synthetic dataset catalogue.
- Access request workflow with pending, approved, rejected, and withdrawn enum states.
- Approval and rejection endpoints using a documented simulated local reviewer.
- Structured audit events.
- Central error handling.
- Local testing, quality, Docker, CI, and documentation foundation.

## Workflow

```mermaid
sequenceDiagram
    participant Researcher
    participant API
    participant Service
    participant Audit
    Researcher->>API: POST /api/v1/access-requests
    API->>Service: validate and create pending request
    Service->>Audit: access_request_submitted
    Researcher->>API: POST approve or reject endpoint
    API->>Service: simulated reviewer decision
    Service->>Audit: approved, rejected, or invalid transition
    API-->>Researcher: stable JSON response
```

## Out of Scope

Milestone 2 and later capabilities were not implemented. This includes production identity, cloud infrastructure, automated security scanners, vulnerability management, release gates, and Security Champions programme material.
