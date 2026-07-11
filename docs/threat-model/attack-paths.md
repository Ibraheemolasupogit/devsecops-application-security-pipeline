# Attack Paths

## Compromised Researcher Identity

```mermaid
flowchart LR
    A["Compromised researcher identity"] --> B["Enumerate access request IDs"]
    B --> C["Object-level authorisation failure"]
    C --> D["Unauthorised metadata or workflow access"]
    D --> E["Incomplete audit detection"]
```

Mapped threats: `THR-AUTH-001`, `THR-AUTHZ-001`, `THR-API-003`, `THR-AUDIT-001`.

## Malicious Dependency Update

```mermaid
flowchart LR
    A["Malicious dependency update"] --> B["CI build compromise"]
    B --> C["Altered container image"]
    C --> D["Future overprivileged deployment identity"]
    D --> E["Runtime compromise"]
```

Mapped threats: `THR-SUPPLY-001`, `THR-SUPPLY-002`, `THR-SUPPLY-003`, `THR-CI-001`, `THR-IAM-001`.

## Future Public Datastore Exposure

```mermaid
flowchart LR
    A["Terraform misconfiguration"] --> B["Datastore publicly reachable"]
    B --> C["Workflow and audit data exposed"]
    C --> D["Incident investigation depends on audit integrity"]
```

Mapped threats: `THR-IAC-001`, `THR-IAC-002`, `THR-IAM-002`, `THR-AUDIT-001`.
