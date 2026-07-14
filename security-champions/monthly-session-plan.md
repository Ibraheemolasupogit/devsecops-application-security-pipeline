# Monthly Session Plan

| Month | Topic | Objective | Preparation | Facilitator | Exercise | Evidence | Follow-up |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Secure design | Review early risk questions | Read design guide | Product Security | Design review | Champion notes | Update checklist |
| 2 | Threat modelling | Map assets and boundaries | Read threat model | Product Security | STRIDE exercise | Threat template | Add requirement gap |
| 3 | Authentication | Validate JWT controls | Read auth guide | Champion | Negative test review | API evidence | Add tests |
| 4 | Authorisation | Check object access | Read authz guide | Champion | Role matrix | Dynamic evidence | Fix gaps |
| 5 | API security | Review endpoints | Read API checklist | Engineering Lead | Endpoint review | API inventory | Update docs |
| 6 | Dependency security | Review package risk | Read SBOM guide | DevSecOps | Finding triage | AppSec evidence | Track fix |
| 7 | Container security | Review image findings | Read container guide | Platform | Trivy triage | Findings evidence | Rebuild plan |
| 8 | Terraform security | Review IaC controls | Read Terraform guide | Cloud Security | Checkov review | Infra evidence | Least privilege action |
| 9 | Finding triage | Prioritise remediation | Read triage guide | Product Security | Canonical finding | Lifecycle evidence | Assign owner |
| 10 | Release assurance | Interpret release gate | Read release guide | Product Security | Conditional pass | Release report | Approval path |
| 11 | Exception governance | Review time limits | Read exception guide | Risk Owner | Exception review | Lifecycle report | Expiry action |
| 12 | Lessons learned | Convert patterns to prevention | Review metrics | Champion | Category review | Metrics report | Next year plan |


## How Champions Use This
Security Champions use this material to help squads ask better questions earlier, run the relevant repository commands, interpret evidence, and escalate risk with context. Champions do not approve formal risk acceptance, own incidents, weaken scanner policy, or replace Product Security accountability. Every activity should leave a clear evidence trail in the repository outputs or reports.

## Evidence
Use `make champions-full` after changing this material. Use `make findings-full`, `make release-full`, `make lifecycle-full`, `make evidence-full`, and `make developer-enablement-full` when the activity changes scanner findings, release decisions, lifecycle state, consolidated evidence, or developer guidance. Success means generated JSON evidence verifies and reports are regenerated from machine-readable data.

## Failure Mode
If evidence does not match the narrative, fix the evidence source or update the guidance. Do not hide findings, rename squads to avoid ownership, extend exceptions without review, or claim attendance that did not happen. Escalate unresolved risk with the relevant finding, release decision, lifecycle record, and proposed next action.
