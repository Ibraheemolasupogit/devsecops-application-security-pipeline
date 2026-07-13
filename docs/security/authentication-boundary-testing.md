# Authentication Boundary Testing

`make auth-boundary-test` runs dynamic tests for missing bearer tokens, malformed tokens, invalid signatures, expired tokens, future `nbf`, wrong issuer, wrong audience, missing subject, missing roles, unknown roles, unsupported algorithms and `none` algorithm attempts.

Expected behaviour is a controlled 401 response, stable error code, `WWW-Authenticate` where appropriate, no stack trace and no raw token content in responses or evidence.
