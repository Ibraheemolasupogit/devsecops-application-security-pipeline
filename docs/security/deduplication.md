# Deduplication

Deduplication is deterministic and exact-key based. It uses CVE + package, CWE + file + line, control + asset, or source-specific stable keys before any title comparison.

No fuzzy matching, probabilistic matching or machine-learning matching is used. Raw evidence is never deleted; duplicate source records are linked in `finding-source-map.json`.

```mermaid
flowchart TD
  A["Canonical source findings"] --> B{"Exact identifier available?"}
  B -->|CVE + package| C["Group"]
  B -->|CWE + file + line| C
  B -->|control + asset| C
  B -->|No| D["Keep source-specific key"]
  C --> E["Primary canonical finding + related IDs"]
  D --> E
```
