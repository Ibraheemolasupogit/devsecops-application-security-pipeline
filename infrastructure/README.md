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
- `terraform/modules/github-oidc` and `github-actions-role`: account-local GitHub identity model plus distinct ECR publisher and QA/production deploy roles.
- `terraform/modules/codebuild-runner`: optional per-environment private CodeBuild-hosted ephemeral runner, webhook, no-inbound SG and non-deploying service role.
- `terraform/environments/nonprod`: one shared QA/test cluster (namespace separation later).
- `terraform/environments/prod`: separate production cluster.
- `terraform/artifacts`: one environment-neutral ECR repository, no extra cluster.
- `terraform/**/tests/*.tftest.hcl`: mock-provider plan assertions and rejection tests.

M5 outputs include publisher/deployer/provider ARNs, cluster name/region, namespace group, and optional CodeBuild project, service role and runner security group. Deploy roles receive only `eks:DescribeCluster` on their intended EKS cluster. EKS access entries map them to separate Kubernetes groups; offline Roles/RoleBindings in `kubernetes/rbac/` grant each group only namespaced workload/configuration governance operations. Namespace creation and governance labels in `kubernetes/platform/` are privileged platform bootstrap work; CI cannot create namespaces, read Secrets, mutate cluster-scoped resources or change RBAC.

CodeBuild projects are conditional on a pre-authorized CodeConnections GitHub App connection ARN. Null example values keep projects and runner SGs absent. A later authorised deployment can configure each project on only its destination VPC private subnets; its SG is admitted to that cluster's private API on TCP 443 with no inbound rules. OIDC authenticates a job to STS; it does not provide VPC routing. The CodeBuild service role is separate and limited to runner logs, VPC ENI lifecycle and use of the bootstrapped source connection. It has no EKS, ECR publish, PassRole or deployment-role assumption permissions. No GitHub or AWS connection credential belongs in this repository.

Each account must own exactly one GitHub OIDC provider. The artifacts, nonprod and prod compositions create one when `github_oidc_provider_arn` is null or reuse the ARN provided by its owner state. If compositions share an AWS account, create the provider in the first state and pass its output to the others; separate accounts each need their own provider. Future jobs route to each project's exact CodeBuild label using the run ID and attempt. The project name is only runner routing; OIDC and namespace RBAC remain separate identity/authorisation controls.

Read [EKS infrastructure](../docs/architecture/eks-infrastructure.md), [cost controls](../docs/engineering/eks-cost-controls.md) and [validation record](../docs/engineering/eks-foundation-validation.md). EKS Terraform pins Terraform 1.16.5 / AWS provider 6.68.0; the ECS reference retains its original constraints. No AWS account, backend, credentials or real resources are assumed.

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

Targets initialize/validate all four EKS roots (bootstrap, artifacts, nonprod, prod) and both ECS reference environments; test runs cover those roots and focused modules using mock providers only. Local Terraform commands use `terraform init -backend=false` where applicable. If Terraform is not installed, the Terraform-specific targets report that and skip without deploying.

## M7 activation boundary

`terraform/bootstrap` is an independent, backend-free state foundation composition for a versioned/private S3 bucket, rotating KMS encryption, TLS-only policy and deletion safeguards. It has not been applied. Backend examples use native S3 lockfiles (`use_lockfile = true`) and distinct `eks/nonprod`, `eks/prod`, and `eks/artifacts` keys. Bootstrap state starts local and must be migrated only after the reviewed bucket exists. Keep the bucket/key outside nonprod teardown.

M7 splits nonprod AWS activation and clean artifact publication from M8 QA deployment. No M7 apply, resource creation, live OIDC, CodeBuild run, ECR push, or Kubernetes deployment is authorized. The validation machine lacked AWS CLI, had Terraform 1.15.8 versus required 1.16.5, and has no selected account/region; thus no live plan or exact resource count is available. See the [activation runbook](../docs/runbooks/nonprod-platform-activation.md), [cost readiness](../docs/engineering/nonprod-aws-cost-readiness.md), and [validation record](../docs/engineering/milestone-7-validation.md).

## Deployment Boundary

Do not run `terraform apply` from this milestone. Backend bootstrap, image publication, certificate provisioning, DNS and live deployment credentials are future operational steps. WAF rules are already modelled in the ECS compute reference, but have not been provisioned.

## Direct safe validation

```bash
terraform -chdir=infrastructure/terraform/environments/nonprod init -backend=false
terraform -chdir=infrastructure/terraform/environments/nonprod validate
terraform -chdir=infrastructure/terraform/environments/prod init -backend=false
terraform -chdir=infrastructure/terraform/environments/prod validate
```

Remote S3 state/KMS/lockfile bootstrap, GitHub CodeConnections authorization and GitHub Environment protections are documented but not created by this repository. Example backend files contain placeholders. Runner infrastructure is modelled but remains disabled while the connection ARN input is null. No live plan/apply, federation, CodeBuild runner execution or Kubernetes application deployment is included.
