# Authorisation Guide

Authorisation is deny-by-default and supports `SR-AUTHZ-001`, `SR-AUTHZ-003`, `SR-AUTHZ-004`, `SR-AUTHZ-005` and `SR-DEV-003`.

Central permissions live in `src/genomic_research_access_api/security/authorisation.py`. Route dependencies require explicit permissions before protected actions. The role-to-permission mapping separates researcher, approver, data custodian, security auditor and application administrator responsibilities. Requester and approver duties are separated so a requester cannot approve or reject their own request.

When adding a new permission, update the permission enum, map roles deliberately, apply the dependency at the route, add negative tests, update API-security evidence and refresh dynamic checks if the endpoint is externally reachable. Run `make api-security-test`, `make dynamic-full`, `make api-security-evidence` and `make verify-api-security-evidence`.

Success means unauthenticated users fail, wrong roles fail, correct roles succeed, and object-level checks still apply. Evidence is in `outputs/security/api-security/authorisation-matrix.json`, `outputs/security/api-security/negative-test-summary.json` and `outputs/security/dynamic/authorisation-boundary-summary.json`.

Do not add catch-all admin bypasses. Admin roles still follow explicit permissions and separation-of-duties rules.

