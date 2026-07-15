# Security Tooling Readiness Report

Overall status: attention_required.

- python: available - Required for all workflows.
- git: available - Required for source control.
- docker_cli: available - Required for container-backed scanners.
- docker_daemon: unavailable - Required for Trivy, ZAP and Docker fallback execution.
- terraform: available - Required for Terraform init/validate/test.
- gitleaks: unavailable - Native binary optional; pinned Docker image is supported.
- trivy: unavailable - Native binary optional; pinned Docker image is supported.
- aws_credentials: not_required - Milestone 11 does not deploy or access AWS.
