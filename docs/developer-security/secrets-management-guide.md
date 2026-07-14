# Secrets Management Guide

Secrets guidance supports `SR-SECRETS-001`, `SR-SUPPLY-004`, `SR-DEV-004` and `SR-EVIDENCE-001`.

No real secrets belong in source, tests, reports, scanner output or evidence. Local JWT material is synthetic and only for development. Terraform may define Secrets Manager metadata and IAM access patterns, but it must not manage secret values. Test fixtures may contain obvious non-secret placeholders only when scanner suppressions are narrow, owned, justified and expiring.

Run `make secrets-scan` before review and `make appsec-full` after changing scanner configuration or Docker paths. Success means Gitleaks completes with no leaks and `outputs/security/appsec/secret-scan-summary.json` reports a pass. Consolidated evidence should also pass sensitive-content checks through `make evidence-full`.

If a secret is accidentally exposed, remove it from the working tree, rotate the real value outside this repository, rerun secret scanning and document the remediation without pasting the value. Do not add broad suppressions, commit environment files or include raw credentials in issue templates.

