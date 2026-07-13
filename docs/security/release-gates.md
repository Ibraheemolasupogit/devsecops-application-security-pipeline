# Release Gates

Release gates evaluate canonical findings and produce one release decision: `pass`, `conditional_pass`, `warn` or `block`.

```mermaid
flowchart TD
    A["deduplicated-findings.json"] --> B["Derive context"]
    B --> C["Evaluate rules"]
    C --> D["Apply precedence"]
    D --> E["Release decision"]
    E --> F["Actions and approvals"]
```

Decision precedence is `block`, then `conditional_pass`, then `warn`, then `pass`.

Evidence mode writes decision evidence regardless of the decision. Enforcement mode maps the decision to a process exit code.
