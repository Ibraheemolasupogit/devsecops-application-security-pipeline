# Input Validation Guide

Input validation supports `SR-API-001`, `SR-API-002` and `SR-LOG-003`.

Use explicit Pydantic schemas for request bodies. Keep enum values narrow, length limits intentional and unexpected fields rejected where the endpoint accepts structured input. Derive security-sensitive fields such as requester identity from the authenticated principal, not from client-supplied JSON. Treat correlation IDs as untrusted input and keep them bounded before logging.

Run `make test`, `make api-security-test` and `make dynamic-full` after changing schemas, route parameters or error handling. Success means malformed bodies fail predictably, oversized fields are rejected, mass assignment is blocked, content-type edge cases are covered and no stack traces leak through API errors. Evidence is reflected in `outputs/security/api-security/negative-test-summary.json`, `outputs/security/dynamic/schema-mutation-summary.json` and `reports/security/negative-security-testing-report.md`.

If a scanner or test finds an input issue, add a regression test first, fix the schema or service boundary, rerun the targeted command and then refresh evidence. Do not document unsupported input shapes as accepted just to satisfy OpenAPI output.
