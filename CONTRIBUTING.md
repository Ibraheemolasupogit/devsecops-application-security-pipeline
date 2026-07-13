# Contributing

This portfolio repository is a local demonstration of a secure product foundation. Contributions should preserve the delivered milestone boundaries and avoid adding cloud deployment, formal exception workflow or vulnerability-management operations before their roadmap milestone.

## Local Checks

Run:

```bash
make quality
make appsec-fast
make dynamic-fast
make findings-full
make release-full
```

Use deterministic synthetic data only. Do not add real patient, NHS, genomic, credential, or cloud account data.

## Development Expectations

- Keep API behavior covered by tests.
- Preserve stable JSON error structures.
- Do not introduce wildcard CORS defaults.
- Do not commit generated caches, local databases, logs, or environment files.
- Run scanner targets after changing dependencies, Dockerfile, Terraform, authentication or request-handling code.
- Keep dynamic-security scans pointed only at localhost, loopback or approved local Docker targets.
- Do not add broad scanner suppressions. Use `security/config/suppressions.yaml` with an owner, expiry and exact path or rule scope.
- Keep findings IDs deterministic and avoid absolute local paths, raw JWTs, private keys or real data in canonical findings outputs.
- Keep release-gate evidence deterministic. Use `make release-gate-enforce` only when you intentionally want enforcement exit codes; evidence-mode release targets must still run for block and conditional decisions.
