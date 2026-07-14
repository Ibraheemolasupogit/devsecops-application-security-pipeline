# Container Security Guide

Container guidance supports `SR-CONTAINER-001`, `SR-CONTAINER-002` and `THR-CONTAINER-001`.

The Dockerfile uses a pinned Python base image, multi-stage build, non-root runtime user and local build target. Do not switch to a floating latest tag, add unnecessary packages, restore package managers into the runtime layer or push images as part of this portfolio workflow. ECS hardening is represented as non-deployed Terraform code.

Run `make container-build-security` and `make container-scan` after Dockerfile or dependency changes. Run `make appsec-full`, `make findings-full`, `make release-full` and `make lifecycle-full` when Trivy output changes. Success means the image builds locally, Trivy completes, no blocking finding is introduced and release evidence explains any conditional findings. Evidence is in `outputs/security/appsec/container-scan-summary.json` and `reports/security/container-security-report.md`.

For unfixed vulnerabilities, review fix availability, package ownership, runtime exposure and release impact. Use lifecycle governance for accepted risk. Do not hide packages, skip the scan or push the image from local validation.

