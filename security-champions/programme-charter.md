# Programme Charter

The programme exists to make secure delivery repeatable inside engineering squads. Its scope covers secure design, threat modelling, local security checks, secure code review, finding triage, remediation support, exception review, learning, and evidence review. Non-goals include deployment, external ticketing, dashboarding, enterprise export, messaging automation, and Repository 5 integration.

Decision rights are explicit: engineers own implementation, champions facilitate and coach, engineering leads prioritise delivery work, Product Security owns policy and assurance, and Risk Owners accept residual risk. Champions collaborate rather than gatekeep and bring Product Security in early when risk is unclear. Success is measured through coverage, ownership, verification, learning actions, and clear escalation, not lower finding counts.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
