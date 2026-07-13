# Remediation Workflow

Remediation starts from the vulnerability register generated from canonical findings:

```bash
make lifecycle-initialise
make lifecycle-validate
```

Owners, SLA dates and priorities come from findings enrichment. Scanner suppressions remain visible as scanner governance metadata; they do not become formal lifecycle exceptions.

```mermaid
flowchart TD
    A["Canonical finding"] --> B["Lifecycle record"]
    B --> C["Owner and SLA assignment"]
    C --> D["Remediation plan"]
    D --> E["Resolved"]
    E --> F["Verification"]
    F --> G["Closed"]
```

The local implementation is file-backed and deterministic. It is not a ticketing system.
