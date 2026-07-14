# Secure Design Review With Design Change, Controls, Assumptions, Tests, Evidence And Follow-Up

Use this template to capture secure design review with design change, controls, assumptions, tests, evidence and follow-up. Keep entries role-based and evidence-backed. Required fields: date, squad, champion role, evidence references, decisions needed, actions, owners, due dates, and escalation status. Do not include personal data, email addresses, raw secrets, JWTs, or unsupported attendance claims.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
