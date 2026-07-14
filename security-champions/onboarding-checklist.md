# Onboarding Checklist

- [ ] Read the programme charter and champion role.
- [ ] Review secure SDLC guidance in `docs/developer-security/secure-development-guide.md`.
- [ ] Run `make quality` and record the result.
- [ ] Review authentication and authorisation guides.
- [ ] Inspect canonical findings and release-gate output.
- [ ] Complete threat modelling, secure code review, and finding triage exercises.
- [ ] Review exception governance and escalation criteria.
- [ ] Run `make champions-full` after any programme material change.

Completion is measurable through checked items, generated champion evidence, and reviewed reports. This is not a real attendance record; it is a repository demonstration path.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
