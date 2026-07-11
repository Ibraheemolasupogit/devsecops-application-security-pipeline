# Milestone 1 Security Foundation

Milestone 1 establishes secure defaults for a local portfolio reference application.

Implemented controls:

- Synthetic, deterministic seed data only.
- No real credentials, patient data, NHS data, or individual-level genomic records.
- Strict enums for dataset and access request states.
- Pydantic request validation with field length limits and whitespace handling.
- Central JSON error responses without stack traces.
- Correlation ID propagation through response headers and error bodies.
- Explicit CORS allow-list for local origins only.
- Structured audit events for dataset views, submissions, approvals, rejections, and invalid transitions.
- Non-root Docker runtime user.
- Local quality gates for formatting, linting, typing, and coverage.

Deferred controls:

- Production authentication and authorisation.
- JWT, OIDC, RBAC, and object-level authorisation.
- Threat modelling and STRIDE registers.
- SAST, SCA, secret scanning, SBOM, IaC scanning, container scanning, DAST, and API fuzzing.
- AWS, Terraform, deployment, release gates, and vulnerability lifecycle workflows.

Milestone 2 now documents these deferred controls in the threat model and requirements register. Documentation of a future control does not mean the control is implemented.
