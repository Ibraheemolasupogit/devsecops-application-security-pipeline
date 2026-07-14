# Communication Guide

Champion communication should be concise, role-based, and evidence-linked. Use repository reports, pull request comments, design notes, and squad ceremonies. Do not use this milestone to send email, Slack messages, calendar invites, Jira tickets, ServiceNow records, or external notifications.

A good update states the risk, affected control, evidence reference, owner, due date, next action, and escalation level. Avoid blame language and avoid metrics that reward hiding findings. Champions should help teams understand why a control matters and how to prove remediation.


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
