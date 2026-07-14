# Repository Integration Boundary

```mermaid
flowchart LR
    Local["Local Security Evidence"] --> Export["Versioned Contract Export"]
    Export --> Validate["Sample Consumer Validation"]
    Validate -. no write .-> Repo5["Repository 5 Boundary"]
```

Boundary: contract export and validation only; no Repository 5 modification.

Evidence: `outputs/security/integration/integration-manifest.json`, `docs/integration/repository-5-integration-contract.md`.
