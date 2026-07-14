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
make evidence-full
make champions-full
make integration-full
```

`findings-full` consumes existing scanner outputs and does not require Docker by itself. `release-full` consumes canonical findings and runs in evidence mode, so it succeeds even when the resulting decision is `block` or `conditional_pass`.

`champions-full` validates the local Security Champions programme configuration, derives metrics from findings and lifecycle evidence, verifies the champion evidence manifest and generates reports. It does not require Docker and does not contact external services.

`integration-full` validates the local Repository 5 integration contract, exports
product-security findings and evidence, validates checksums and sensitive-content
controls, and generates integration reports. It does not contact Repository 5 or
transfer data externally.

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

## Consolidated Evidence

```bash
make evidence-full
```

This verifies source evidence manifests, writes consolidated evidence, verifies checksums and content safety, and generates audience-oriented reports. It does not refresh Docker-backed scanner evidence.

## Security Champions

```bash
make champions-full
```

This validates synthetic role-based champion configuration, metrics, maturity, escalation, evidence and reports. It does not create tickets, send messages, track real attendance, integrate Repository 5 or deploy anything.

## Integration Contract

```bash
make integration-full
python3 examples/integration-consumer/validate_bundle.py outputs/security/integration
```

A consumer control plane can use the manifest and checksums to validate the bundle
before ingestion. This repository does not implement live ingestion.
