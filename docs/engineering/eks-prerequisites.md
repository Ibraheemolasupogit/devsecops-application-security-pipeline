# EKS Foundation Prerequisites

M3 readiness audit, 2026-10-11. This document installs nothing, provisions nothing and does not configure live credentials. Existing Terraform remains a non-deployed ECS reference. EKS is the primary future runtime; M3 must introduce a separate composition/state without rewriting that reference.

## Required for M3 implementation and local validation

| Prerequisite | Current evidence | M3 requirement |
| --- | --- | --- |
| Terraform | Existing constraint >=1.8.0,<2.0.0; CI 1.8.5; local 1.15.8 | Select and pin one maintained compatible version for the new foundation; document parity. If using S3 lockfile locking, require Terraform >=1.10 and update validation setup deliberately; 1.8.5 cannot support it |
| AWS provider/modules | Existing ~>5.70 with dev/prod provider lockfiles | Review supported EKS features/provider requirements, constrain versions and commit platform checksums; do not assume ECS versions support all target identity/access features |
| Python/Make/dev/security tools | Project >=3.11, CI 3.11/3.12, local Python 3.12.8 | Use the repository .venv on PATH for all checks so upgraded pins are actually exercised; preserve exact direct pins and scanner inventory |
| AWS CLI v2 | Not found on current PATH | Not necessary to author/fmt offline HCL; required for authenticated planning/identity preflight. Confirm current EKS authentication requirements before use |
| kubectl/Kustomize | kubectl executable present | Required for later rendering/access tests; match kubectl supported skew to chosen cluster version; Kustomize is the sole app packaging model |
| Docker | CLI 28.3.3; daemon unavailable | Needed for full local image/Trivy/Schemathesis/ZAP checks. CLI presence is insufficient; docker info must succeed. Do not automatically start/install tooling |
| GitHub CLI | gh present | Useful for environment/check/artifact inspection; optional for HCL implementation. No auth changes or pushes in M2 |

Terraform fmt, policy tests and init -backend=false/validate need no AWS deployment account, though provider downloads need network. An authenticated Terraform plan can read AWS data and requires account permissions; distinguish it from offline validation. Terraform absence currently causes wrapper skips; a skipped check is not a passed infrastructure validation.

## Required only before actual AWS deployment

1. **Accounts and billing:** approved AWS account(s), region, budget/uptime ceiling, service quotas and named owners. AWS uses accounts/billing rather than an Azure subscription model. Prefer non-prod/prod accounts, separate VPC/state/roles, one shared non-prod cluster plus a production cluster. No account existence is assumed or queried here.
2. **Region:** explicitly chosen region with EKS, instance/AZ and relevant identity/add-on support. Check IP capacity, quotas, endpoint/service availability and costs. Keep application resources regional; do not infer a region from local timezone. Use synthetic data only.
3. **Remote state/bootstrap:** provision through a separately authorised bootstrap before foundation apply. Encrypted/versioned/private S3 state, least-privilege key access, locking, separate environment keys/state and recovery test. Prefer S3 lockfile with compatible Terraform; existing DynamoDB-lock examples are historical and locking-table state is separate from the app database. Backend credentials/values must not enter Git. [HashiCorp S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3).
4. **Bootstrap IAM:** trusted short-lived operator identity; reviewed permissions for state S3/KMS, IAM/OIDC roles/policies, VPC/endpoints/security groups, EKS/access entries/node groups/EC2, logs and ECR. Restrict PassRole to named cluster/node/controller roles, attach permission boundaries, scope service-specific resources/tags and separate key administration. Account/SCP restrictions must be validated. The broad ECS reference deployment policy is not the production bootstrap policy. Exact actions must follow the reviewed M3 plan; do not default to AdministratorAccess.
5. **GitHub OIDC:** exact repository/audience/provider trust; qa and production GitHub Environments, branch/reviewer protections and role separation; publisher/deploy/bootstrap roles cannot be interchangeable. Existing IAM references an OIDC provider but does not create it. Protect state and production approvals; no static AWS CI keys. M5 proves operational federation; M3 designs role boundaries.
6. **ECR:** private encrypted immutable repository, approved publish/pull identities, cross-account policy if selected, retention protecting active/rollback digests. Existing ECR is reference Terraform only; no repository/images exist by implication.
7. **EKS:** selected supported cluster version and upgrade owner; private API/runner path, AZ/subnet capacity, managed-node role/access, CNI/network-policy enforcement, encryption/logging, workload identity agent/SDK/controller compatibility. Controller/node credentials must not substitute for workload permissions. Decide NAT versus endpoints using actual required EKS Auth/STS/ECR/S3/logs/secret/IdP connectivity and cost.
8. **Deployment authorisation:** reviewed plan/cost/destroy design, explicit approval to create resources and account identity check. No Terraform apply, destroy, AWS mutation or deployment is authorised by this prerequisites document.

[Official EKS setup guidance](https://docs.aws.amazon.com/eks/latest/userguide/setting-up.html) describes AWS CLI and Kubernetes access tooling; Terraform is this programme's provisioning tool, so eksctl is not a second provisioning path.

## Optional later-stage tooling and decisions

DNS/domain/Route 53 and ACM certificate ownership are optional for initial foundation validation but required before public HTTPS application ingress. No domain purchase/certificate issuance in M2/M3 authoring. ESO/ALB controllers, OTel/log collectors, AWS test IdP, signing/attestation tools and kind/minikube belong to their later milestones. Do not install Helm alongside Kustomize for this app. AWS CLI/kubectl are necessary for real platform operations, not a reason to block documentation/offline policy tests. GitHub CLI is useful but no external issue/PR creation is needed.

Scanner prerequisites: .venv security extras, native Gitleaks/Trivy or their configured container fallback, CycloneDX, network for advisory databases/provider downloads, and a running Docker daemon for image build/dynamic containers. Local target allowlists remain enforced. Tool-unavailable/execution failures must remain visible; don't substitute fixtures as fresh scans. Direct Python pins do not fully lock transitive dependencies; M6 must address reproducible image resolution.
