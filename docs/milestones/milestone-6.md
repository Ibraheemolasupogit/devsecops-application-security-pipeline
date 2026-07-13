# Milestone 6: API and Dynamic Security Validation

Milestone 6 adds local-only dynamic validation for the Genomic Research Access API.

Implemented controls:

- Dynamic pytest boundary tests for authentication, authorisation, object-level access, input mutation, security headers, CORS, resource consumption and audit events.
- Pinned Schemathesis container execution against the local OpenAPI schema.
- Pinned OWASP ZAP baseline scan against the local API only.
- Local target safeguards for `127.0.0.1`, `localhost`, `::1`, `host.docker.internal` and the approved Docker service name `api`.
- Bounded in-memory application rate limiter for deterministic dynamic tests.
- Deterministic evidence under `outputs/security/dynamic/` and reports under `reports/security/`.

Milestone 6 does not add release gates, canonical finding normalisation, risk scoring, exception workflow, cloud deployment, Redis, API Gateway or external scanning.
