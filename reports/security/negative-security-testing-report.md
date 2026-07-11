# Negative Security Testing Report

| Category | Value |
| --- | --- |
| Test file | tests/security/test_api_security_controls.py |
| Covered cases | missing bearer token, expired JWT, clock-skew boundary, future not-before JWT, wrong issuer, wrong audience, invalid signature, unsupported signing algorithm, none signing algorithm, malformed token, missing subject, missing roles, unknown role, insufficient role for approval, insufficient role for audit access, approver permitted review access, administrator permitted audit access, cross-user access request read, restricted dataset without entitlement, self approval, self rejection, mass assignment payload, disallowed CORS origin, malformed correlation identifier |
| Expected statuses | authentication_failures: 401, authorisation_failures: 403, hidden_object_failures: 404, schema_failures: 422 |
| Security audit events | authentication_succeeded, authentication_failed, authorisation_denied, access_request_viewed, self_approval_denied, audit_events_viewed |
