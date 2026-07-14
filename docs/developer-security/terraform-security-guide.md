# Terraform Security Guide

Terraform guidance supports `SR-IAC-001`, `SR-IAC-002`, `SR-IAM-001`, `SR-IAM-002`, `SR-DATA-002`, `SR-DATA-003` and `SR-LOG-002`.

Terraform in this repository is a non-deployed reference architecture. Keep module boundaries clear, environment inputs separate, provider versions pinned and state security assumptions explicit. Review IAM least privilege, network exposure, KMS keys, Secrets Manager metadata, CloudTrail, logging and deletion protection when changing infrastructure code.

Run `make terraform-fmt-check`, `make terraform-init`, `make terraform-validate`, `make terraform-test`, `make infrastructure-test` and `make checkov-scan`. Success means Terraform validates locally, infrastructure tests pass, Checkov has no failed checks and evidence verifies through `make infrastructure-evidence` and `make verify-infrastructure-evidence`. Reports include `reports/security/terraform-security-report.md`, `reports/security/iam-security-report.md` and `reports/security/aws-architecture-report.md`.

Do not run Terraform apply as part of ordinary development or CI. Do not add AWS credentials, deployment jobs or real secret values. If Checkov flags a valid issue, fix the Terraform or document a narrow governed suppression with expiry.

