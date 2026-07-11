# Contributing

This portfolio repository is a local demonstration of a secure product foundation. Contributions should keep Milestone 1 focused on the FastAPI reference application and avoid adding later roadmap capabilities prematurely.

## Local Checks

Run:

```bash
make quality
```

Use deterministic synthetic data only. Do not add real patient, NHS, genomic, credential, or cloud account data.

## Development Expectations

- Keep API behavior covered by tests.
- Preserve stable JSON error structures.
- Do not introduce wildcard CORS defaults.
- Do not commit generated caches, local databases, logs, or environment files.
- Keep future security tooling, AWS, Terraform, and production authentication out of Milestone 1 unless the roadmap milestone changes.
