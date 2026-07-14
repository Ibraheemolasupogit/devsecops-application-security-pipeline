# System Context

```mermaid
flowchart LR
    Developer["Developer"] --> API["Genomic Research Access API"]
    Security["Product Security"] --> Evidence["Security Evidence"]
    API --> Evidence
    Evidence --> Portfolio["Portfolio Reports"]
    Evidence --> Contract["Repository 5 Contract Export"]
```

Boundary: local repository, local evidence and contract export only.

Evidence: `outputs/security/evidence/evidence-manifest.json`, `outputs/security/portfolio/portfolio-manifest.json`.
