# Milestone 9: Vulnerability Lifecycle and Exception Governance

Milestone 9 adds deterministic local vulnerability lifecycle governance over canonical findings and release-assurance outputs.

Implemented:

- Typed lifecycle package under `src/genomic_research_access_api/security/lifecycle/`.
- Versioned policy under `config/lifecycle/`.
- Deterministic vulnerability register, exception register, history, CSV exports, summary and evidence manifest under `outputs/security/lifecycle/`.
- Lifecycle schemas under `schemas/security/lifecycle/`.
- Reports under `reports/security/`.
- Make targets from `lifecycle-policy-validate` through `lifecycle-full`.
- A pinned GitHub Actions workflow that validates lifecycle evidence without Docker.
- Tests for state transitions, verification-before-closure, false positives, exception expiry, deterministic evidence and reports.

Out of scope:

- Milestone 10 Security Champions.
- Production workflow system integration.
- Cloud deployment, container push, AWS resource creation, commit or push automation.
- Personal actor identity. Lifecycle history uses approved actor roles only.
