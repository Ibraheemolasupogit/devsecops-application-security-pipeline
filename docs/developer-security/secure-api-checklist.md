# Secure API Checklist

Use this checklist for new or changed endpoints. It supports `SR-API-001`, `SR-API-002`, `SR-API-003`, `SR-API-004`, `SR-API-005`, `SR-AUTH-001`, `SR-AUTHZ-001` and `SR-AUTHZ-002`.

- Authentication is required for protected routes.
- Authorisation is explicit and deny-by-default.
- Object-level access is checked in the service layer.
- Pydantic schemas reject malformed input and unexpected fields.
- Content types are expected and errors are stable JSON.
- Correlation IDs are bounded and safe for logs.
- Security headers and CORS remain explicit.
- Rate limiting or local resource controls still behave predictably.
- Audit events are generated for significant workflow actions.
- OpenAPI output still represents the endpoint accurately.

Run `make api-security-test`, `make dynamic-fast`, `make dynamic-full` and `make evidence-full` when endpoint behaviour changes. Success means tests pass, dynamic summaries are current and the consolidated evidence bundle verifies. Relevant outputs include `outputs/security/api-security/endpoint-security-inventory.json`, `outputs/security/dynamic/schema-mutation-summary.json` and `reports/security/dynamic-security-report.md`.

When a check fails, fix the endpoint, schema or dependency first. Evidence includes `outputs/security/dynamic/schema-mutation-summary.json`. Do not add broad CORS origins, hide errors with untested handlers or skip dynamic tests for externally reachable routes.
