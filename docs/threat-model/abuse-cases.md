# Abuse Cases

| Abuse Case | Mapped Threats |
| --- | --- |
| Researcher attempts to access an unapproved dataset | `THR-API-003`, `THR-AUTHZ-001` |
| Researcher attempts to approve their own request | `THR-AUTHZ-002`, `THR-AUTHZ-003` |
| Attacker enumerates access-request identifiers | `THR-AUTHZ-001`, `THR-API-003` |
| Attacker submits oversized or malformed payloads | `THR-API-001`, `THR-API-002`, `THR-API-005` |
| Compromised approver approves inappropriate access | `THR-AUTHZ-003`, `THR-AUDIT-001` |
| Attacker manipulates correlation IDs to disrupt traceability | `THR-AUDIT-004`, `THR-AUDIT-003` |
| Developer commits a credential | `THR-SECRETS-001` |
| Compromised dependency alters API behaviour | `THR-SUPPLY-001`, `THR-SUPPLY-002` |
| CI/CD identity is abused to publish a malicious image | `THR-CI-001`, `THR-SUPPLY-003` |
| Future Terraform change exposes a datastore publicly | `THR-IAC-002` |
| Attacker attempts to suppress or forge audit records | `THR-AUDIT-001` |
