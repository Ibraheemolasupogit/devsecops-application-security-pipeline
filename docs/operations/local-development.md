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

## Docker

```bash
make docker-build
make docker-run
```

The container exposes port `8000` and serves the same local API. It does not require external services or cloud credentials.

## Local State

Access requests and audit events are in memory. Restarting the app resets runtime-created state. Dataset seed data is deterministic.
