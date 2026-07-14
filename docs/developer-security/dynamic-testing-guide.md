# Dynamic Testing Guide

Dynamic testing supports `SR-API-004`, `SR-API-005`, `SR-AUTH-001`, `SR-AUTHZ-001`, `SR-AUTHZ-002` and `SR-DEV-004`.

Dynamic scans are local-only. Targets must remain localhost, loopback or approved local Docker routes. Schemathesis validates the OpenAPI surface, ZAP runs a bounded local baseline, and pytest covers authentication boundaries, authorisation boundaries, object access, input mutation, headers, CORS, rate limiting and audit behaviour.

Run `make dynamic-fast` while coding and `make dynamic-full` before review when endpoints, schemas, auth, headers, CORS or resource controls changed. Docker and local server binding are required for the full path. Success means dynamic pytest passes, the local health check returns OK, Schemathesis and ZAP complete, and `make dynamic-evidence` plus `make verify-dynamic-evidence` succeed.

Evidence is in `outputs/security/dynamic/` and reports such as `reports/security/dynamic-security-report.md`, `reports/security/schemathesis-report.md` and `reports/security/zap-report.md`. If the local server cannot bind, use the troubleshooting guide; do not point scanners at external services.

