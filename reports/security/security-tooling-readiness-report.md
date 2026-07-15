# Security Tooling Readiness Report

Overall status: ready_with_fallbacks.

- python: available - Required for all workflows.
- git: available - Required for source control.
- docker_cli: available - Required for container-backed scanners.
- docker_daemon: available - Required for Trivy, ZAP and Docker fallback execution.
- terraform: available - Required for Terraform init/validate/test.
- gitleaks: available_via_fallback - Native binary optional; pinned Docker image is supported.
- trivy: available_via_fallback - Native binary optional; pinned Docker image is supported.
- aws_credentials: not_required - Milestone 11 does not deploy or access AWS.
