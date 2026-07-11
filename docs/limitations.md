# Limitations

- This is not a production genomics platform.
- This repository is not affiliated with or endorsed by Genomics England.
- All data is synthetic, deterministic, and non-identifiable.
- Runtime state is stored in memory and resets on restart.
- Local JWT keys under `tests/fixtures/keys/` are synthetic development material and are not production secrets.
- The audit event API is for local demonstration only and is restricted by role.
- External identity-provider integration, AWS, Terraform, production rate limiting, immutable audit logging, and AppSec scanners are intentionally deferred.
