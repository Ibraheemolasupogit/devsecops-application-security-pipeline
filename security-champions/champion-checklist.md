# Champion Checklist

Use this checklist when a change introduces a new endpoint, data flow, role, permission, dependency, Terraform resource, container base image, scanner suppression, exception, external integration, or release decision. Ask what changed, which control is affected, which command proves the change, which evidence updates, and whether escalation is needed.

A champion should confirm threat-model impact, authentication and authorisation boundaries, object-level access, input validation, logging, secret handling, dependency risk, infrastructure impact, scanner results, release-gate impact, and lifecycle state. The checklist supports review; it is not a substitute for Product Security decision rights.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
