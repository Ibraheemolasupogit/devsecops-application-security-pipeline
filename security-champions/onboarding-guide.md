# Onboarding Guide

The onboarding path introduces the programme, repository architecture, secure SDLC, threat modelling, authentication and authorisation controls, AppSec tools, dynamic testing, findings model, release gates, lifecycle governance, exceptions, evidence, and escalation.

```mermaid
flowchart LR
  Intro[Programme introduction] --> Repo[Repository controls]
  Repo --> Tools[Local security tools]
  Tools --> Evidence[Evidence and reports]
  Evidence --> Practice[Workshop practice]
  Practice --> Review[90 day review]
```

New champions first read `docs/developer-security/README.md`, run `make quality`, review `reports/security/release-gate-report.md`, inspect canonical findings, and complete at least the threat modelling, secure code review, and finding triage workshops in synthetic training mode.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
