# Milestone 7 - Findings Normalisation and Risk Enrichment

Milestone 7 converts security outputs from threat modelling, AppSec scanners, infrastructure evidence and local dynamic API testing into one canonical product-security findings model.

It implements a versioned Pydantic schema, deterministic finding IDs, source adapters, exact-key deduplication, asset enrichment, ownership assignment, transparent risk scoring, remediation SLA dates and deterministic evidence.

This milestone does not implement release gates, vulnerability lifecycle states, formal exception approval, dashboards, ticketing integrations or deployment.

## Validation

Use:

```bash
make findings-full
make verify-findings-evidence
make findings-report
```

The workflow uses existing source evidence. It does not refresh Docker-backed scanner output unless the AppSec or dynamic scanner targets are run separately.
