# Release Gate Guide

Release-gate guidance supports `SR-RELEASE-001`, `SR-RELEASE-002`, `SR-RELEASE-003`, `SR-RELEASE-004` and `SR-DEV-002`.

The release gate evaluates canonical findings in evidence mode by default. Outcomes are pass, warn, conditional_pass and block. Blocking rules take precedence over warnings and conditional approvals. Required approvals depend on severity, ownership, fix availability, suppression state, due dates, exceptions and environment policy.

Run `make release-full` to refresh evidence. Use `make release-gate-enforce` only when you intentionally need enforcement exit codes. Success means `outputs/security/release/release-gate-decision.json` explains the decision, required approvals and actions. Current local evidence may produce conditional_pass, but that is an example outcome, not a permanent state.

Review `reports/security/release-gate-report.md`, `reports/security/release-risk-report.md` and `reports/security/release-assurance-report.md`. If a decision is unexpected, run `make findings-full`, inspect canonical findings and rerun release evaluation. Do not delete findings, broaden suppressions or weaken gate rules to obtain a pass.

