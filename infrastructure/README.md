# Infrastructure — EKS foundation and retained ECS reference

This directory contains the primary **non-deployed EKS Terraform foundation** and the retained **non-deployed ECS/Fargate reference alternative** for the Genomic Research Access API.

It is intended for local validation and future deployment planning only. It does not create AWS resources unless an operator explicitly runs Terraform with real backend, provider and account configuration.

## Reference boundary and EKS programme

Terraform at the existing root, modules/ and environments/dev and environments/prod belongs to the retained **non-deployed ECS/Fargate reference alternative**. It is not the primary target for the EKS delivery programme. The primary EKS foundation now lives in terraform/ with separate nonprod, prod and shared artifact states. These are not the similarly named ECS reference environments.

The reference stays in place because scanners, policy tests, manifests and documentation use these paths. Moving it now would cause avoidable churn without creating a runtime boundary. M3 adds a clearly separated EKS composition/state; do not repurpose/apply the ECS environments as an EKS foundation. Reuse reviewed control intent, not broad IAM policies or ECS assumptions blindly. Physical archival can occur later only with verifier/contract parity.

See [ECS → EKS decision](../docs/architecture/0007-ecs-to-eks.md), [target platform](../docs/architecture/target-devsecops-platform.md), [migration roadmap](../docs/architecture/eks-migration-roadmap.md), and [M3 prerequisites](../docs/engineering/eks-prerequisites.md).

## Primary EKS structure

- `terraform/modules/{networking,iam,kms,logging,eks,ecr}`: reusable cloud foundations.
- `terraform/modules/platform`: common cluster composition.
- `terraform/environments/nonprod`: one shared QA/test cluster (namespace separation later).
- `terraform/environments/prod`: separate production cluster.
- `terraform/artifacts`: one environment-neutral ECR repository, no extra cluster.
- `terraform/**/tests/*.tftest.hcl`: mock-provider plan assertions and rejection tests.

Read [EKS infrastructure](../docs/architecture/eks-infrastructure.md), [cost controls](../docs/engineering/eks-cost-controls.md) and [validation record](../docs/engineering/eks-foundation-validation.md). Terraform 1.15.8 / AWS provider 6.21.0 are pinned for EKS; the ECS reference retains its original constraints. No AWS account, backend, credentials or real resources are assumed.

## Retained ECS structure

- `environments/dev`: lower-cost development composition.
- `environments/prod`: production-oriented composition with stronger validation defaults.
- `modules/networking`: VPC, subnets, routing, endpoints and security groups.
- `modules/kms`: customer-managed KMS keys and aliases.
- `modules/iam`: deployment, GitHub OIDC, execution and runtime role model.
- `modules/secrets`: Secrets Manager metadata without secret values.
- `modules/ecr`: encrypted immutable ECR repository.
- `modules/compute`: ALB, ECS Fargate task definition and service.
- `modules/datastore`: DynamoDB table with KMS encryption and recovery controls.
- `modules/observability`: CloudWatch logs and alarms.
- `modules/audit`: CloudTrail and secure audit buckets.
- `tests`: local policy tests that require no AWS account.

## Validation

```bash
make terraform-fmt
make terraform-fmt-check
make terraform-init
make terraform-validate
make terraform-test
make infrastructure-test
make infrastructure-evidence
make verify-infrastructure-evidence
make infrastructure-report
```

Targets initialize/validate all three EKS roots and both ECS reference environments; test runs cover the EKS roots and three focused modules using mock providers only. Local Terraform commands use `terraform init -backend=false` where applicable. If Terraform is not installed, the Terraform-specific targets report that and skip without deploying.

## Deployment Boundary

Do not run `terraform apply` from this milestone. Backend bootstrap, image publication, certificate provisioning, DNS and live deployment credentials are future operational steps. WAF rules are already modelled in the ECS compute reference, but have not been provisioned.

## Direct safe validation

```bash
terraform -chdir=infrastructure/terraform/environments/nonprod init -backend=false
terraform -chdir=infrastructure/terraform/environments/nonprod validate
terraform -chdir=infrastructure/terraform/environments/prod init -backend=false
terraform -chdir=infrastructure/terraform/environments/prod validate
```

Remote S3 state/KMS/lockfile bootstrap is documented but not created. Example backend files contain placeholders. A real operator/runner private access path and approved add-on versions are prerequisites; no live plan/apply or Kubernetes application configuration is included. M4 consumes outputs for Kustomize workload/readiness work; M5 establishes operational CI/workload identity boundaries.
