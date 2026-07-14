# Secure Code Review Guide

Secure review supports `SR-DEV-002`, `SR-DEV-003`, `SR-DEV-004` and `THR-REVIEW-001`.

Review identity trust first. Confirm protected endpoints require authentication, roles are explicit, object ownership is checked and state transitions cannot be forced by request body fields. Look for mass assignment, unexpected fields, unsafe subprocess usage, broad exception handling, raw token logging, weak secret handling and dependency risk.

For infrastructure, review network exposure, IAM scope, KMS use, secret metadata, logging and state assumptions. For containers, review base image pins, non-root runtime, package additions and Trivy impact. For governance, review new suppressions, exceptions, lifecycle changes and release-gate outcomes.

Ask the author to run `make quality`, relevant targeted security commands, `make findings-full`, `make release-full`, `make lifecycle-full` and `make evidence-full`. Success means evidence supports the claim in the pull request, not just that code looks reasonable. If evidence is stale, request regeneration rather than approving on narrative alone.

