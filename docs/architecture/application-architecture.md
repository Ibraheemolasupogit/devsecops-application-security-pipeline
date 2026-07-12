# Application Architecture

The repository implements a small FastAPI service named Genomic Research Access API. It uses deterministic synthetic data and in-memory repositories so the full application remains runnable locally with no AWS account or external service.

```mermaid
flowchart TB
    Client["HTTP client"] --> Middleware["Correlation and security header middleware"]
    Client --> Authn["JWT authentication dependency"]
    Authn --> Authz["Role permission dependency"]
    Middleware --> Router["FastAPI routers"]
    Authz --> Router
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
- Authentication validates local RS256 JWTs and exposes a central principal.
- Authorisation maps roles to permissions and applies object-level checks in services.

## Extension Points

The repository and service boundaries are intentionally simple. Later milestones can replace in-memory persistence, integrate an external identity provider, attach scanner or cloud controls, and add durable policy storage without redesigning the API foundation.

## Milestone 2 Security Architecture

Milestone 2 adds a validated threat model without changing runtime API behaviour.

```mermaid
flowchart LR
    Source["Machine-readable threat-model registers"] --> Validator["Threat-model validator"]
    Validator --> Evidence["Deterministic evidence JSON"]
    Validator --> Reports["Generated Markdown reports"]
    Evidence --> CI["CI evidence verification"]
    App["Milestone 1 FastAPI app"] --> Source
```

The threat model analyses both the current local implementation and anticipated cloud-native context. Future identity, AWS, Terraform and scanner controls are modelled as planned controls only.

## Milestone 3 API Security Architecture

```mermaid
flowchart LR
    Request["/api/v1 request"] --> Bearer["Authorization bearer token"]
    Bearer --> Validator["RS256 JWT validator"]
    Validator --> Principal["AuthenticatedPrincipal"]
    Principal --> Permission["Role-to-permission matrix"]
    Permission --> Route["Protected route"]
    Route --> ObjectRule["Object-level service rule"]
    ObjectRule --> Audit["Security audit event"]
```

All `/api/v1/*` routes require authentication and explicit permissions. `/health` and local OpenAPI documentation remain public for local development. Restricted dataset detail and access-request resources are checked per object; unauthorised object access returns a not-found style response to avoid confirming resource existence.

## Milestone 4 AWS Reference Architecture

Milestone 4 adds Terraform configuration for a future AWS deployment blueprint. It is not deployed.

```mermaid
flowchart LR
    Client["Internet client"] --> ALB["Application Load Balancer"]
    ALB --> ECS["ECS Fargate service in private subnets"]
    ECS --> DynamoDB["DynamoDB access-governance table"]
    ECS --> Secrets["Secrets Manager metadata"]
    ECS --> Logs["CloudWatch Logs"]
    Trail["CloudTrail"] --> S3["Private encrypted S3 audit bucket"]
    DynamoDB --> KMS["KMS keys"]
    Secrets --> KMS
    Logs --> KMS
    S3 --> KMS
```

The Terraform implementation separates deployment, execution and runtime roles, keeps ECS tasks private, avoids Terraform-managed secret values and generates deterministic infrastructure evidence under `outputs/security/infrastructure/`.

## Milestone 5 AppSec Pipeline Architecture

```mermaid
flowchart LR
    Source["Repository source"] --> Wrappers["scripts/appsec_tools.py"]
    Wrappers --> SAST["Semgrep and Bandit"]
    Wrappers --> SCA["pip-audit and SBOM"]
    Wrappers --> IaC["Checkov"]
    Wrappers --> Image["Gitleaks and Trivy when available"]
    SAST --> Evidence["outputs/security/appsec"]
    SCA --> Evidence
    IaC --> Evidence
    Image --> Evidence
    Evidence --> Reports["reports/security"]
```

The scanner pipeline is local and CI-oriented. It does not publish images, create cloud resources or implement vulnerability-management workflow states.
