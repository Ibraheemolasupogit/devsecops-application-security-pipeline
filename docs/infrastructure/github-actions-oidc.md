# GitHub Actions OIDC

The IAM module defines a reference deployment role that trusts GitHub Actions through OIDC.

Trust restrictions:

- Federated principal: `token.actions.githubusercontent.com`.
- Audience: `sts.amazonaws.com`.
- Subject: `repo:${github_repository}:${github_ref}`.
- Repository and branch or environment are variables, not personal identifiers.

```mermaid
sequenceDiagram
    participant GHA as GitHub Actions
    participant OIDC as GitHub OIDC token
    participant STS as AWS STS
    participant Role as Deployment role
    GHA->>OIDC: request short-lived identity token
    GHA->>STS: AssumeRoleWithWebIdentity
    STS->>Role: validate audience and subject
    Role-->>GHA: short-lived credentials
```

CI in this repository does not configure AWS credentials yet and does not deploy.
