# Contributing

This portfolio repository is a local demonstration of a secure product foundation. Contributions should preserve the delivered milestone boundaries and avoid adding cloud deployment, release gates or vulnerability-management operations before their roadmap milestone.

## Local Checks

Run:

```bash
make quality
make appsec-fast
make dynamic-fast
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
