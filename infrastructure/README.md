# Infrastructure — Retained ECS/Fargate Reference

This directory contains a non-deployed AWS ECS Fargate reference architecture for the Genomic Research Access API.

It is intended for local validation and future deployment planning only. It does not create AWS resources unless an operator explicitly runs Terraform with real backend, provider and account configuration.

## Reference boundary and EKS programme

All existing Terraform in this directory, including environments/dev and environments/prod, belongs to the retained **non-deployed ECS/Fargate reference alternative**. It is not the primary target for the EKS delivery programme. EKS becomes the primary architecture target in M3; no EKS modules/composition exist yet and none are introduced in M2.

The reference stays in place because scanners, policy tests, manifests and documentation use these paths. Moving it now would cause avoidable churn without creating a runtime boundary. M3 must add a clearly separated EKS composition/state and label its ownership; do not repurpose/apply the ECS environments as an EKS foundation. Reuse reviewed control intent, not broad IAM policies or ECS assumptions blindly. Physical archival can occur later only with verifier/contract parity.

See [ECS → EKS decision](../docs/architecture/0007-ecs-to-eks.md), [target platform](../docs/architecture/target-devsecops-platform.md), [migration roadmap](../docs/architecture/eks-migration-roadmap.md), and [M3 prerequisites](../docs/engineering/eks-prerequisites.md).

## Structure

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

Local Terraform commands use `terraform init -backend=false` where applicable. If Terraform is not installed, the Terraform-specific targets report that and skip without deploying.

## Deployment Boundary

Do not run `terraform apply` from this milestone. Backend bootstrap, image publication, certificate provisioning, DNS and live deployment credentials are future operational steps. WAF rules are already modelled in the ECS compute reference, but have not been provisioned.
