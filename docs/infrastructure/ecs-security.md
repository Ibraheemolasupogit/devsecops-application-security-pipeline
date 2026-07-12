# ECS Security

The compute module defines:

- ECS cluster with container insights.
- Fargate task definition.
- ECS service in private subnets.
- Deployment circuit breaker with rollback.
- ALB target group and health checks.
- CloudWatch log configuration.
- Separate task execution and runtime roles.

Container hardening:

- Image URI is supplied by variable.
- Production image must use a SHA-256 digest.
- `:latest` is rejected.
- Container runs as user `10001`.
- `readonlyRootFilesystem` is enabled.
- `privileged` is false.
- Linux capabilities are dropped.
- Only the application port is exposed.

No image is published by this milestone.
