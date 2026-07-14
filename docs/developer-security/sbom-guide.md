# SBOM Guide

SBOM guidance supports `SR-SUPPLY-002`, `SR-EVIDENCE-001` and `SR-DEV-004`.

The repository generates a deterministic CycloneDX SBOM for dependency visibility. Run `make sbom` after dependency changes and `make verify-sbom` before review. Run `make appsec-full` when the dependency change also affects container image contents or vulnerability findings. Success means the SBOM JSON is valid, dependencies are represented and the AppSec evidence manifest includes a checksum for the output.

Use the SBOM with `make dependency-audit`, `make container-scan`, `make findings-full` and `make release-full` to understand overlap between Python package findings and container findings. Evidence is in `outputs/security/appsec/sbom.cdx.json`, `outputs/security/appsec/evidence-manifest.json` and `reports/security/sbom-report.md`.

If SBOM validation fails, fix the generator or dependency metadata and regenerate. Do not edit generated SBOM JSON manually, omit a dependency from packaging to silence a scanner, or treat SBOM generation as a deployment or provenance statement.

