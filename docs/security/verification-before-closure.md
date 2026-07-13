# Verification Before Closure

Closure requires passed verification evidence and closure evidence. A resolved vulnerability cannot move directly to closed.

```mermaid
flowchart TD
    A["resolved"] --> B{"Verification passed?"}
    B -- "yes" --> C["verified"]
    C --> D["closed"]
    B -- "no" --> E["in_remediation"]
```

Critical and high findings require an independent verifier role according to `config/lifecycle/verification-policy.yaml`.

Verification records are exported to `outputs/security/lifecycle/verification-register.json`.
