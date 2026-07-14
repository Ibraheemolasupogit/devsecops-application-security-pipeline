# Security Champions Programme

This package defines the local Security Champions operating model for the repository. It is synthetic, role-based, and evidence-backed. It scales engineering ownership through squad champions while Product Security remains accountable for policy, assurance, release risk, and formal risk acceptance.

```mermaid
flowchart LR
  SE[Software Engineer] --> SC[Security Champion]
  SC --> EL[Engineering Lead]
  SC --> PS[Product Security]
  PS --> RO[Risk Owner]
  PE[Platform Engineering] --> SC
```


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
