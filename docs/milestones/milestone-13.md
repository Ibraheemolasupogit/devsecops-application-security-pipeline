# Milestone 13: Repository 5 Integration Contract

Milestone 13 implements a local, versioned, deterministic export contract for product
security findings and assurance evidence.

Delivered:

- `product-security-control-plane-export` contract version `1.0`.
- Integration package under `src/genomic_research_access_api/security/integration/`.
- Schemas under `schemas/security/integration/`.
- Config under `config/integration/`.
- Export bundle under `outputs/security/integration/`.
- Sample local consumer validation under `examples/integration-consumer/`.
- Reports under `reports/security/`.
- CI workflow `.github/workflows/integration-contract.yml`.

Boundary:

- Repository 9 owns product AppSec evidence, canonical findings, release assurance,
  lifecycle state, verification evidence and export generation.
- A consumer control plane can validate and ingest the bundle.
- Repository 5 is not modified, accessed, deployed to or assumed.

Not implemented: live API integration, queueing, S3 transfer, dashboards, ticketing,
AWS resources, deployment, external upload or Milestone 14 work.

