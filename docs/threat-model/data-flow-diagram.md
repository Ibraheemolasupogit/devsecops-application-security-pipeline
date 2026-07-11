# Data Flow Diagrams

## Current Local Architecture

```mermaid
flowchart LR
    Client["External/local client"] -->|"HTTP requests"| App["FastAPI app"]
    App -->|"validated models"| Service["Service layer"]
    Service -->|"read/write"| Repo["In-memory repositories"]
    Service -->|"structured events"| Audit["Audit service"]
    Audit -->|"append"| AuditRepo["In-memory audit repository"]
```

## Access-Request Workflow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Service
    participant Repo
    participant Audit
    Client->>API: POST /api/v1/access-requests
    API->>Service: validated AccessRequestCreate
    Service->>Repo: create pending request
    Service->>Audit: access_request_submitted
    API-->>Client: 201 pending request
```

## Approval and Rejection Workflow

```mermaid
stateDiagram-v2
    [*] --> pending
    pending --> approved: approve with simulated reviewer
    pending --> rejected: reject with simulated reviewer
    approved --> approved: invalid transition rejected
    rejected --> rejected: invalid transition rejected
```

## Audit-Event Flow

```mermaid
flowchart LR
    Action["Dataset view or workflow action"] --> Service["Service layer"]
    Service --> Event["Audit event builder"]
    Event --> Store["In-memory audit store"]
    Store --> LocalEndpoint["Current local demo endpoint"]
    Store -. future .-> CloudLogs["Future central audit logging"]
```

## Anticipated Cloud-Native Architecture

```mermaid
flowchart LR
    User["Future authenticated user"] -.-> Edge["Future API edge/TLS"]
    Edge -.-> Runtime["Future container runtime"]
    IdP["Future identity provider"] -. tokens .-> Runtime
    Runtime -.-> Store["Future private datastore"]
    Runtime -.-> Logs["Future cloud logging"]
    CICD["Future CI/CD"] -. deploy .-> Runtime
    Registry["Future container registry"] -. image .-> Runtime
```

## Trust Boundaries

```mermaid
flowchart TB
    Internet["External client zone"] -->|"TB-001"| API["API routing zone"]
    API -->|"TB-002"| Services["Application services zone"]
    Services -->|"TB-003"| Repos["Repository zone"]
    Services -->|"TB-004"| Audit["Audit zone"]
    Dev["Developer workstation"] -->|"TB-005"| Repo["Source repository"]
    Repo -->|"TB-006"| CI["CI build environment"]
    CI -. "TB-007 future" .-> Cloud["Future cloud control plane"]
    Runtime["Future runtime"] -. "TB-008 future" .-> Data["Future datastore/logging"]
    Public["Future public network"] -. "TB-009 future" .-> Private["Future private components"]
    Runtime -. "TB-010 future" .-> Secrets["Future secrets and encryption services"]
```
