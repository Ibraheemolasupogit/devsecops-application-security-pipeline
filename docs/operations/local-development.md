# Local Development

## Setup

```bash
make setup
```

## Run

```bash
make run
```

The API listens on `http://127.0.0.1:8000`.

## Quality Checks

```bash
make quality
```

This runs formatting checks, linting, mypy, and coverage-enforced tests.

It also runs authentication/API-security tests and verifies committed threat-model and API-security evidence.

## AppSec Checks

```bash
make appsec-fast
```

This runs Semgrep rule tests, SAST, project-scoped dependency audit, SBOM validation, Checkov reporting and AppSec evidence verification. Docker-backed secret and container scans are available through `make secrets-scan` and `make container-scan` when Docker is running.

## Dynamic API Security Checks

```bash
make dynamic-fast
make dynamic-full
```

`dynamic-fast` runs local in-process API security tests. `dynamic-full` adds local API startup, pinned Schemathesis OpenAPI testing, pinned OWASP ZAP baseline scanning, deterministic evidence verification and report generation. Do not override scan targets to external hosts.

## Findings Normalisation

```bash
make findings-full
```

This consumes existing source evidence and writes canonical findings, CSV exports, risk/ownership/SLA summaries and reports. It does not refresh Docker-backed scanner output by itself.

## Release Assurance

```bash
make release-full
```

This validates release policy, evaluates canonical findings, writes release evidence, verifies deterministic checksums and generates reports. Evidence mode is intentionally separate from enforcement.

```bash
make release-gate-enforce
```

The enforcement target returns nonzero for `block` and for missing approvals on `conditional_pass`.

## Local API Tokens

Protected `/api/v1/*` routes require a bearer token. Generate synthetic local tokens with:

```bash
make dev-token-researcher
make dev-token-approver
make dev-token-auditor
```

Use the emitted token as `Authorization: Bearer <token>`. The local private key is synthetic test material in `tests/fixtures/keys/` and must not be reused outside this repository.

## Docker

```bash
make docker-build
make docker-run
```

The container exposes port `8000` and serves the same local API. It does not require external services or cloud credentials.

## Local State

Access requests and audit events are in memory. Restarting the app resets runtime-created state. Dataset seed data is deterministic.
