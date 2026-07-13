# Security Evidence Model

The consolidated evidence bundle is generated with:

```bash
make evidence-full
```

```mermaid
flowchart LR
    A["Source manifests"] --> B["Source validation"]
    B --> C["Consolidated evidence"]
    C --> D["Metrics"]
    C --> E["Control coverage"]
    C --> F["Reports"]
    C --> G["Evidence manifest"]
```

The model records source manifests, checksums, domains, release decision, finding counts, lifecycle counts, exception counts, verification counts and limitations. It is local portfolio evidence, not production certification.
