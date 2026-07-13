# Local Security Workflow

For local AppSec, dynamic security, findings and release-assurance work:

```bash
make appsec-full
make dynamic-full
make findings-full
make verify-findings-evidence
make findings-report
make release-full
make verify-release-evidence
make lifecycle-full
make verify-lifecycle-evidence
```

`findings-full` consumes existing scanner outputs and does not require Docker by itself. `release-full` consumes canonical findings and runs in evidence mode, so it succeeds even when the resulting decision is `block` or `conditional_pass`.

Use enforcement explicitly when a release decision should become a shell exit code:

```bash
make release-gate-enforce
```

The enforcement target returns nonzero for `block` and for `conditional_pass` when required approvals are missing.

## Vulnerability Lifecycle

```bash
make lifecycle-full
```

This verifies findings and release evidence, validates lifecycle policy, initialises the vulnerability and exception registers, evaluates exception expiry, writes deterministic evidence, verifies checksums and generates lifecycle reports. It does not require Docker.
