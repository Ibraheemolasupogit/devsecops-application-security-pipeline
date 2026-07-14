# Getting Started Securely

This path gets a new contributor from clone to a verified local security workflow. It supports `SR-DEV-001`, `SR-AUTH-001`, `SR-AUTHZ-001` and `SR-EVIDENCE-001`.

## Prerequisites

Install Python 3.11 or later, Git, Docker Desktop and Terraform. Docker is required for container-backed Gitleaks, Trivy, Schemathesis and ZAP paths. Terraform is required for `make terraform-init`, `make terraform-validate` and `make terraform-test`. Run `make security-doctor` to see whether each prerequisite is available, available through a fallback, unavailable or not required.

## First Setup

Run `make setup` to create `.venv` and install dependencies. Run `make run` to start the API on localhost. Generate a local synthetic token with `make dev-token-researcher`, `make dev-token-approver` or `make dev-token-auditor`. Do not paste generated tokens into issues, pull requests or committed files. Use the token only in a local request to a protected endpoint, then discard it.

## First Checks

Run `make quality` for formatting, linting, typing, tests, coverage and core evidence verifiers. Run `make appsec-fast` for secrets, SAST and dependency checks. Run `make dynamic-full` after starting Docker to exercise local-only dynamic security checks. Then run `make findings-full`, `make release-full`, `make lifecycle-full` and `make evidence-full`.

Success is a clean command exit and verified manifests under `outputs/security/`. If setup fails, read `docs/developer-security/troubleshooting-security-tools.md`; do not skip scanners, disable tests or use deployment commands to work around local setup issues.

