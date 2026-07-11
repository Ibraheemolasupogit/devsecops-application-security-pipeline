# Authentication

Protected `/api/v1/*` routes require `Authorization: Bearer <token>`.

The local implementation validates RS256 JWTs with configured issuer and audience checks. Tokens must include `sub`, `roles`, `exp`, `iat` and `jti`; `nbf` is honoured when present. The validator rejects unsupported algorithms, malformed tokens, invalid signatures, expired tokens, wrong issuer, wrong audience, missing subject and unknown roles.

Local development tokens are signed with synthetic keys under `tests/fixtures/keys/`.

```bash
make dev-token-researcher
make dev-token-approver
make dev-token-auditor
```

These keys and tokens are local development material only. A production deployment would replace them with a trusted external identity provider and production key management.
