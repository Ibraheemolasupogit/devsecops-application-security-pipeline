# Troubleshooting Security Tools

Troubleshooting supports `SR-DEV-001` and `SR-DEV-004`.

| Symptom | Likely cause | Safe resolution | What not to do |
| --- | --- | --- | --- |
| Docker daemon unavailable | Docker Desktop is stopped. | Start Docker and rerun `make security-doctor`. | Do not skip `make appsec-full` when Docker evidence changed. |
| Docker socket denied | Sandbox cannot access the socket. | Rerun the same command with approved elevated execution. | Do not change scanner policy. |
| Local server cannot bind | Port or sandbox bind restriction. | Stop the other process or rerun approved local validation. | Do not scan external targets. |
| Terraform unavailable | CLI is missing. | Install Terraform before Terraform targets. | Do not run cloud apply commands. |
| Terraform init required | Modules are not initialized. | Run `make terraform-init`. | Do not commit `.terraform` directories. |
| Gitleaks native binary missing | Native install is absent. | Use the pinned Docker fallback through `make secrets-scan`. | Do not disable secret scanning. |
| Trivy native binary missing | Native install is absent. | Use the pinned Docker fallback through `make container-scan`. | Do not skip image scanning. |
| Checkov Prisma warning | Optional guideline lookup failed. | Confirm local summary still shows failed 0. | Do not add network credentials. |
| ZAP out-of-date warning | Scanner image has an upstream notice. | Record it if scan completed. | Do not treat the warning as proof of failure. |
| Coverage below threshold | Tests do not cover changed code. | Add focused tests and rerun `make test-coverage`. | Do not lower coverage threshold. |
| Evidence checksum mismatch | Generated output changed. | Regenerate the source evidence and rerun verifier. | Do not hand-edit manifests. |
| Dirty worktree metadata | Evidence records local changes. | Review the diff and regenerate before commit. | Do not claim the tree is clean. |
| Stale generated outputs | Scanner or report inputs changed. | Rerun the relevant full target. | Do not commit stale reports. |

Use `make developer-enablement-full` to verify this guide and the command inventory.

