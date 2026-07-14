# Authentication Guide

Authentication is implemented locally with synthetic RS256 JWTs and supports `SR-AUTH-001`. Production identity-provider integration remains outside this milestone.

Run `make dev-token-researcher`, `make dev-token-approver` or `make dev-token-auditor` to create a local token for manual API testing. The token must include expected issuer, audience, subject, role, expiry, not-before and JWT ID claims. Supported roles are researcher, approver, data custodian, security auditor and application administrator. Token lifetime is intentionally short for local testing.

Use `make auth-test` and `make api-security-test` to verify protected endpoint behaviour. Dynamic authentication boundary coverage is generated through `make dynamic-full` and summarized in `outputs/security/dynamic/authentication-boundary-summary.json`.

Common failures include missing token, expired token, unsupported algorithm, invalid signature, wrong issuer, wrong audience, unknown role or malformed structure. Success means protected endpoints reject invalid tokens and accept only valid local synthetic identities.

Never log raw tokens. Do not paste them into pull requests, issues, scanner suppressions or evidence. If a token appears in source or evidence, run `make secrets-scan`, remove the value, rotate any affected local material and regenerate evidence.

