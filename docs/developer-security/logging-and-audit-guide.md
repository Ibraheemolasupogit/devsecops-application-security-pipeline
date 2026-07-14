# Logging and Audit Guide

Logging and audit guidance supports `SR-LOG-001`, `SR-LOG-003`, `SR-LOG-004` and `SR-EVIDENCE-001`.

Audit events are local demonstration evidence for significant workflow actions. Logs and audit outputs must avoid raw tokens, private keys, credentials, patient data and absolute local paths. Correlation IDs should help trace a request without becoming an injection path or a secret container. Audit retrieval is role-limited and is not presented as a production audit architecture.

Run `make api-security-test`, `make dynamic-full`, `make findings-full` and `make evidence-full` after changing audit generation, error handling or correlation behaviour. Success means audit actions still appear for workflow changes, unauthorized audit access fails, dynamic checks pass and consolidated evidence contains no sensitive patterns. Evidence is in `outputs/security/api-security/audit-control-summary.json`, `outputs/security/dynamic/audit-validation-summary.json` and `reports/security/evidence-integrity-report.md`.

If a log or report contains sensitive data, remove it, add a regression test or validation rule, rerun `make secrets-scan` and regenerate affected evidence. Do not add real operational contact details or production monitoring claims.
