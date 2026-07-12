# IAM Security Report

| Control | Value |
| --- | --- |
| Deployment role | GitHub Actions OIDC deployment role |
| Task execution role | ECS task start permissions only |
| Runtime role | Application DynamoDB, secret read and KMS use only |
| Static AWS keys | not configured |
| Wildcard actions | False |
| GitHub OIDC audience restricted | True |
| GitHub OIDC subject restricted | True |
