# Milestone 12 - Security Champions Programme

Milestone 12 adds a local, synthetic, evidence-backed Security Champions operating model. It defines the programme charter, champion role, onboarding, 90-day plan, monthly learning cadence, workshops, exercises, checklists, escalation model, metrics, maturity model, deterministic evidence and reports.

Validation commands:

```bash
make champions-policy-validate
make champions-metrics
make champions-evidence
make verify-champions-evidence
make champions-report
make champions-full
```

Evidence is written to `outputs/security/champions/`. Reports are written to `reports/security/security-champions-report.md`, `reports/security/champion-coverage-report.md`, `reports/security/champion-maturity-report.md`, `reports/security/champion-workshop-report.md` and `reports/security/champion-escalation-report.md`.

The milestone does not implement Repository 5 integration, enterprise export, dashboards, external messaging, ticketing, real attendance tracking, production identity integration, deployment or AWS resources.
