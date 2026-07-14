# AWS Reference Architecture

```mermaid
flowchart TB
    ALB["Application Load Balancer"] --> ECS["ECS Fargate Service"]
    ECS --> DDB["DynamoDB"]
    ECS --> SM["Secrets Manager Metadata"]
    ECS --> CW["CloudWatch Logs"]
    CT["CloudTrail"] --> S3["Audit Bucket"]
```

Boundary: Terraform reference architecture only; no apply or resource creation.

Evidence: `infrastructure/README.md`, `outputs/security/infrastructure/evidence-manifest.json`.
