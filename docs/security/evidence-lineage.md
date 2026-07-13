# Evidence Lineage

Milestone 10 writes lineage to `outputs/security/evidence/evidence-lineage.json`.

```mermaid
flowchart TD
    A["Threat model"] --> B["Security requirements"]
    B --> C["Implementation references"]
    C --> D["Tests"]
    D --> E["Scanner outputs"]
    E --> F["Canonical findings"]
    F --> G["Release decision"]
    G --> H["Lifecycle records"]
    H --> I["Consolidated report"]
```

Lineage edges include source and target references, relationships, control IDs, threat IDs and security requirement IDs where repository artefacts support them.
