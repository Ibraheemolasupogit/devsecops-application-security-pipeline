# Limitations

- This is not a production genomics platform.
- This repository is not affiliated with or endorsed by Genomics England.
- All data is synthetic, deterministic, and non-identifiable.
- Runtime state is stored in memory and resets on restart.
- Local JWT keys under `tests/fixtures/keys/` are synthetic development material and are not production secrets.
- The audit event API is for local demonstration only and is restricted by role.
- External identity-provider integration, AWS deployment, production rate limiting, immutable audit-log operations, release gates and vulnerability-management operations are intentionally deferred.
- AWS Terraform is present as a reference architecture only; no resources are deployed.
- Terraform validation is skipped locally when Terraform is unavailable and is configured for CI through a pinned setup action.
- Gitleaks and Trivy local execution require native binaries or a running Docker daemon for pinned container fallbacks.
- Checkov findings are captured as reporting evidence in Milestone 5; full Terraform remediation is not claimed.
