# AWS Reference Architecture

Milestone 4 defines a non-deployed AWS ECS Fargate reference architecture. The Terraform is locally validated as configuration only; no AWS resources are created by this repository state.

```mermaid
flowchart TB
    Internet["Internet client"] --> ALB["Application Load Balancer (public subnets)"]
    ALB --> ECS["ECS Fargate service (private app subnets)"]
    ECS --> DDB["DynamoDB access-governance table"]
    ECS --> Secrets["Secrets Manager metadata"]
    ECS --> Logs["CloudWatch Logs"]
    DDB --> DataKMS["KMS application-data key"]
    Secrets --> SecretKMS["KMS secrets key"]
    Logs --> AuditKMS["KMS audit key"]
    CloudTrail["Multi-region CloudTrail"] --> AuditBucket["Private S3 audit bucket"]
    AuditBucket --> AuditKMS
```

## Trust Zones

```mermaid
flowchart LR
    Public["Public zone: ALB only"] --> PrivateApp["Private application zone: ECS tasks"]
    PrivateApp --> PrivateAWS["AWS service endpoints: ECR, Logs, Secrets, S3, DynamoDB"]
    PrivateApp --> Data["Managed data plane: DynamoDB"]
    Trail["AWS management plane"] --> Audit["Audit storage zone: S3 and KMS"]
```

## Deployment Boundary

Terraform files are a deployment blueprint. This milestone does not run `terraform apply`, publish images, create certificates, configure DNS, create WAF rules, or configure live AWS credentials.

## Security Scanning

Milestone 5 adds Checkov scanning for the Terraform reference architecture. Findings are captured in `outputs/security/appsec/iac-scan-summary.json` and are intentionally not hidden behind broad suppressions.
