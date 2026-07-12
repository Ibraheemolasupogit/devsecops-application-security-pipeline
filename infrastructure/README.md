# Infrastructure

This directory contains a non-deployed AWS ECS Fargate reference architecture for the Genomic Research Access API.

It is intended for local validation and future deployment planning only. It does not create AWS resources unless an operator explicitly runs Terraform with real backend, provider and account configuration.

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

Do not run `terraform apply` from this milestone. Backend bootstrap, image publication, certificate provisioning, DNS, WAF rules and deployment credentials are future operational steps.
