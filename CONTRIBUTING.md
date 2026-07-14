# Contributing

This portfolio repository is a local demonstration of a secure product foundation. Contributions should preserve the delivered milestone boundaries and avoid adding cloud deployment, production vulnerability-management operations or Security Champions workflow before their roadmap milestone.

## Local Checks

Run:

```bash
make quality
make appsec-fast
make dynamic-fast
make findings-full
make release-full
make lifecycle-full
make evidence-full
make developer-enablement-full
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
- Keep lifecycle evidence deterministic. Scanner suppressions may inform lifecycle records, but only security exceptions under `config/lifecycle/` and `outputs/security/lifecycle/` may support risk acceptance or deferral.
- Keep consolidated evidence deterministic. Update `config/evidence/source-registry.yaml` when adding a source domain, and do not add reports with manually maintained counts.
- Use `docs/developer-security/README.md` for the secure development workflow, command tiers, pull-request expectations and troubleshooting.
- Complete `.github/pull_request_template.md` for every pull request. Do not paste real secrets, raw tokens, private keys or raw scanner logs.
- Run `make security-doctor` when Docker, Terraform, Gitleaks, Trivy, ZAP or local dynamic checks fail locally.
- Keep scanner suppressions narrow, owned and expiring. Use formal lifecycle exceptions only for time-bound accepted risk or deferral with rationale and approval.
- Regenerate findings, release, lifecycle, consolidated evidence and developer enablement evidence when the corresponding source material changes.
- Commits should preserve milestone boundaries. Do not add deployment, AWS execution, dashboards, external ticketing or Security Champions workflow before their roadmap milestone.
