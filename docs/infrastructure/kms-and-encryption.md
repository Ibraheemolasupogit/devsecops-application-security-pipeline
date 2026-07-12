# KMS And Encryption

The KMS module defines separate customer-managed keys for:

- Application data, including DynamoDB.
- Secrets Manager secrets.
- Audit and logging data, including CloudTrail and CloudWatch logs.

Each configured key enables rotation, uses a deletion window, has an alias and has a scoped key policy. Key administration is assigned to the deployment role. Key usage is limited to the runtime role, execution role or AWS logging services as appropriate.

This split increases operational complexity but keeps secret, application-data and audit-use cases separable for future production reviews.
