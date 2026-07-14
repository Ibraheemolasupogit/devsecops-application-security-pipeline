# Champion Escalation Report

Escalation keeps squad handling close to the work while preserving Product Security and Risk
Owner decision rights.

| Trigger | Level | Required evidence |
| --- | --- | --- |
| critical secret | product_security_escalation | secret scan finding, affected path, rotation status |
| authentication bypass | product_security_escalation | failing auth test, endpoint, affected role |
| authorisation or object-level bypass | engineering_lead_escalation | negative test, object boundary, affected role |
| unowned critical or high finding | champion_escalation | canonical finding, squad mapping, due date |
| overdue P1 or expired exception | risk_owner_escalation | lifecycle record, exception record, release impact |
| release block or failed verification | product_security_escalation | release decision, verification record, required action |
| repeated vulnerability category | squad_handling | findings by category, learning action, owner |
| tooling failure affecting assurance | engineering_lead_escalation | failed command, tool version, affected evidence domain |
