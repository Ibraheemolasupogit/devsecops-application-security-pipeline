# Object-Level Authorisation Guide

Object-level authorisation addresses broken object-level access risks and supports `SR-AUTHZ-002`, `SR-AUTHZ-003` and `SR-DEV-003`.

The current code checks access to restricted datasets, access requests and audit records according to actor role and relationship to the object. When adding a new object type or route, identify the owner, requester, approver, auditor and custodian views before writing the handler. The service layer should derive actor identity from the authenticated principal rather than request body fields.

Run `make api-security-test` for negative access tests and `make dynamic-full` for object-access dynamic checks. Success means a user cannot access another user's request unless the role grants that action, restricted dataset details remain controlled, and audit access remains role-limited. Evidence is in `outputs/security/dynamic/object-access-summary.json` and `reports/security/object-access-report.md`.

If a test fails, do not weaken the role matrix. Fix the service predicate, add a regression test and regenerate API or dynamic evidence. If a product decision needs broader access, update the threat model and release evidence before review.

