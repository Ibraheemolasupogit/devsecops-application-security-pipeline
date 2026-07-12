# AWS Architecture Report

| Area | Configured Value |
| --- | --- |
| Deployment status | not deployed |
| Compute | AWS ECS Fargate |
| Edge | Application Load Balancer |
| Datastore | DynamoDB |
| Network | VPC, public ALB subnets, private ECS subnets, VPC endpoints |
| Supporting services | ECR, Secrets Manager, KMS, CloudWatch, CloudTrail, S3 audit bucket |
