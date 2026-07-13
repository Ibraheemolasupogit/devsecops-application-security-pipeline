# Evidence Verification

Use:

```bash
make evidence-source-validate
make evidence-generate
make verify-consolidated-evidence
make evidence-report
make evidence-full
```

```mermaid
flowchart LR
    A["Source verifiers"] --> B["Source registry"]
    B --> C["Aggregate"]
    C --> D["Verify consolidated checksums"]
    D --> E["Generate reports"]
```

`evidence-full` does not require Docker when existing source evidence is present and verified.
