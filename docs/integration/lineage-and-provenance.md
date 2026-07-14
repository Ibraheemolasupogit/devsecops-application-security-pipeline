# Lineage And Provenance

`outputs/security/integration/finding-source-lineage.json` records source-to-export
edges:

```mermaid
flowchart LR
  A["Raw scanner record"] --> B["Canonical finding"]
  B --> C["Lifecycle record"]
  B --> D["Release evaluation"]
  B --> E["Export record"]
```

Every edge includes source ID, target ID, relationship, domains, references and a
SHA-256 checksum.

