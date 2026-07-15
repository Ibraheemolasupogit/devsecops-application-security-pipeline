# Final Limitations Report

Portfolio ID: `PF-a85617c55bbdd219`

Readiness status: `ready_with_limitations`

Release decision: `conditional_pass`

## Key Metrics

- Canonical findings: 44
- Source findings: 46
- Evidence domains: 9
- Control coverage: 96.67%
- Integration export records: 44
- Repository integration lineage edges: 178

## Readiness Failures

- None

## Limitations

- Application security evidence is locally validated and the platform is not deployed.
- AWS architecture is a Terraform reference implementation only.
- Repository 5 integration is contract-only and does not write to another repository.
- Release decision remains conditional_pass because known non-blocking findings are governed.
