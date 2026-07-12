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
