# Product Security Export Schema

The export schema is generated at
`schemas/security/integration/product-security-finding.schema.json`.

Each record preserves canonical finding identity, source finding IDs, source tools,
lifecycle status, release impact, owner roles, SLA data, exception metadata,
verification status, source evidence references and producer metadata.

Missing repository evidence is represented as `null`; consumer-side enterprise IDs are
not fabricated.

```mermaid
flowchart TD
  A["Canonical finding"] --> B["Export record"]
  C["Lifecycle record"] --> B
  D["Release evaluation"] --> B
  E["Exception evidence"] --> B
  F["Source map"] --> B
```

