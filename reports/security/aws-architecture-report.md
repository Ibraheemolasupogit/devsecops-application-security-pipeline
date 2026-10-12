# AWS Architecture Report

| Area | Configured Value |
| --- | --- |
| Deployment status | not deployed |
| Reference compute | AWS ECS Fargate |
| Primary target | Amazon EKS managed node groups |
| Primary status | configured, not deployed |
| Edge | Application Load Balancer |
| Datastore | DynamoDB |
| Network | VPC, public ALB subnets, private ECS subnets, VPC endpoints |
| Supporting services | ECR, Secrets Manager, KMS, CloudWatch, CloudTrail, S3 audit bucket |
