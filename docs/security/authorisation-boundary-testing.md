# Authorisation Boundary Testing

`make authorisation-boundary-test` verifies runtime role boundaries.

Covered cases include researcher approval/rejection denial, researcher audit denial, approver audit denial, auditor approval/rejection denial and deny-by-default behaviour for unknown roles through authentication-boundary tests.

Evidence is written to `outputs/security/dynamic/authorisation-boundary-summary.json`.
