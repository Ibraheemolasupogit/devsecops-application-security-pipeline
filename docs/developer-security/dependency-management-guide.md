# Dependency Management Guide

Dependency guidance supports `SR-SUPPLY-001`, `SR-SUPPLY-002`, `SR-DEV-004` and `THR-SUPPLY-001`.

When adding a dependency, pin the version in `pyproject.toml`, explain why it is needed and run `make dependency-audit`, `make sbom`, `make verify-sbom`, `make appsec-full`, `make findings-full`, `make release-full` and `make lifecycle-full`. The SBOM is CycloneDX evidence; pip-audit checks Python packages; Trivy may also surface package vulnerabilities from the built image.

Success means no unexpected known vulnerabilities, SBOM validation passes, canonical findings are updated and the release gate reflects the current risk. Evidence lives in `outputs/security/appsec/dependency-scan-summary.json`, `outputs/security/appsec/sbom.cdx.json`, `outputs/security/findings/deduplicated-findings.json` and `outputs/security/release/release-gate-decision.json`.

If a vulnerability has no fix, review severity, exploitability, ownership and release impact. Use a narrow scanner suppression only for scanner noise. Use a formal exception only for time-bound accepted risk with rationale, approval and expiry. Do not unpin versions or hide the dependency from SBOM generation.

