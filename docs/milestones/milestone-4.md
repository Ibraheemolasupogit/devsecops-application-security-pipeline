# Milestone 4

Milestone 4 implements a secure AWS Terraform reference architecture for the Genomic Research Access API without deploying resources.

Delivered:

- ECS Fargate architecture in private subnets behind an Application Load Balancer.
- Secure VPC, subnets, endpoints, route tables, security groups and flow logs.
- ECR repository with KMS encryption, immutable tags, scan-on-push and lifecycle policy.
- DynamoDB access-governance table with KMS encryption, point-in-time recovery and production deletion protection.
- Secrets Manager metadata without Terraform-managed secret values.
- KMS keys for application data, secrets and audit/logging.
- CloudWatch logs and basic infrastructure alarms.
- Multi-region CloudTrail with encrypted private S3 audit storage.
- Separate deployment, GitHub OIDC, task execution, runtime and flow-log roles.
- Local policy tests and deterministic infrastructure evidence.

Not delivered:

- AWS deployment.
- Terraform apply.
- Live DNS, ACM issuance or WAF rules.
- Cognito or external OIDC integration.
- Checkov, Trivy, Semgrep, Gitleaks, Bandit, pip-audit or other scanner pipelines.
