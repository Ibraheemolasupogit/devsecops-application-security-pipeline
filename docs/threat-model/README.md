# Threat Model

This directory contains the Milestone 2 security architecture and threat model for the Genomic Research Access API.

The source of truth is the machine-readable register set:

- `assets.yaml`
- `actors.yaml`
- `entry-points.yaml`
- `trust-boundaries.yaml`
- `data-flows.yaml`
- `threat-register.yaml`
- `security-requirements.yaml`
- `control-traceability.yaml`
- `residual-risk-register.yaml`

These files use JSON-compatible YAML and are validated by:

```bash
make threat-model-validate
```

Deterministic evidence and reports are generated separately:

```bash
make threat-model-evidence
make verify-threat-model-evidence
make threat-model-report
```

This repository uses synthetic, non-identifiable demonstration data only. It is not a production genomics platform and is not affiliated with or endorsed by Genomics England. No production cloud environment is currently deployed.
