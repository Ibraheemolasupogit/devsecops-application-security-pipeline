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

Milestone 9 lifecycle evidence consumes release outputs and exposes lifecycle metadata back to release assurance consumers:

```mermaid
flowchart LR
    A["Canonical findings"] --> B["Release gate"]
    B --> C["Release decision"]
    A --> D["Lifecycle register"]
    C --> D
    D --> E["Exception and verification status"]
    E --> F["Release assurance metadata"]
```

Lifecycle evidence does not change the Milestone 8 release gate decision engine. It records vulnerability status, exception status, expiry, owner, overdue state and verification state for audit and downstream review.
