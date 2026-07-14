# 90 Day Plan

Days 1-30 focus on understanding controls, tools, risks, and squad context. The champion reads developer guidance, maps squad work to threat and requirement IDs, runs local checks, and reviews current findings.

Days 31-60 focus on facilitation. The champion supports secure design review, finding triage, exception review, and remediation verification. Evidence should include refreshed findings, release, lifecycle, and champions reports when relevant.

Days 61-90 focus on leading lightweight security activity. The champion identifies repeated vulnerability categories, proposes learning topics, helps close actions, and escalates unresolved risk with evidence. Outcomes are measured by owner assignment, verification, exception review, and documented learning actions.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
