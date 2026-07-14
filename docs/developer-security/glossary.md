# Glossary

This glossary supports developer onboarding and `SR-DEV-001`.

- AppSec: Application security scanner workflow using Gitleaks, Semgrep, Bandit, pip-audit, CycloneDX, Checkov and Trivy.
- Canonical finding: Normalised finding record under `outputs/security/findings/`.
- Conditional pass: Release-gate outcome that allows evidence-mode continuation with required approvals or actions.
- Consolidated evidence: Milestone 10 bundle under `outputs/security/evidence/`.
- Dynamic security: Local-only API validation using pytest, Schemathesis and ZAP.
- Evidence manifest: JSON file that lists output files and checksums.
- Formal exception: Time-bound lifecycle risk acceptance or deferral with rationale, owner, approval and expiry.
- Scanner suppression: Narrow scanner-level handling for noise or controlled fixtures; it is not risk acceptance.
- Security doctor: `make security-doctor`, which reports local prerequisite readiness without installing software.
- Verification: Independent confirmation that remediation or generated evidence is valid.

Useful commands include `make quality`, `make appsec-full`, `make dynamic-full`, `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full` and `make developer-enablement-full`.

Evidence that confirms the glossary-linked workflow includes `outputs/security/developer-enablement/command-inventory.json`, `outputs/security/developer-enablement/developer-control-mapping.json` and `reports/security/developer-enablement-report.md`.

