# DynamoDB Security

The datastore module defines a DynamoDB table for access-governance state such as access requests, entitlements and audit index metadata. It does not store genomic content.

Controls:

- KMS server-side encryption.
- Point-in-time recovery.
- Production deletion protection.
- `PAY_PER_REQUEST` billing mode for the reference configuration.
- Primary key and secondary index design for access-governance records.
- Tags for ownership and classification.

Production lifecycle preconditions reject disabled point-in-time recovery or deletion protection.
