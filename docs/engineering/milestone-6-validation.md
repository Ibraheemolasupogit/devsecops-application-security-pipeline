# Milestone 6 validation record

This file records the M6 code and command outcomes after implementation and the subsequent real-image validation. The image was built once locally; no image was pushed.

The baseline began on clean `main` at M5 commit `7bc2106` (`Implement GitHub OIDC and private EKS deployment foundation`). `make quality` and `make final-validation` passed at baseline. `make appsec-full` completed secret scanning, SAST, pip-audit, SBOM and Checkov, then stopped at `container-build-security` because the Docker CLI could not connect to the local daemon. The sandboxed pip-audit attempt initially could not reach the package advisory service; the approved network-enabled rerun reported no known vulnerabilities. Checkov reported 484 passed, 0 failed and 42 skipped (138 resources); its optional guideline lookup had a local certificate-chain warning. `git diff --check` passed. Baseline generators modified only deterministic tracked evidence and reports; those paths were restored to the initially clean M5 commit before source edits.

Docker Desktop was subsequently made available (Docker 28.3.3, Buildx 0.27.0-desktop.1). The malformed stale ref `.git/refs/remotes/origin/main 2` was confirmed to point to an old commit and removed; the valid `origin/main` ref was unchanged. Gitleaks then reported two historical marker-only false positives in an M4 commit. Inspection confirmed both contained only the PEM begin marker; the detector was made more precise to require a complete PEM-shaped block with a base64 body and end marker. `make secrets-scan` then passed across 28 commits with no leaks.

The runtime base is pinned to `python:3.11.17-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce`. One `linux/amd64` candidate build completed for source commit `7bc2106054f197fdd432ce11412aede926764812`; the resulting Buildx digest was `sha256:4cf7c5e4472e227388bb9fed5b87781bc1b8d0833dc699edce96f3116bee28ec`. That exact digest is recorded consistently by image metadata, the 109-component Trivy CycloneDX container SBOM, the Trivy image scan summary, provenance, publication decision, and release artifact. Runtime validation succeeded as UID/GID 10001 with a read-only root filesystem, bounded writable `/tmp`, no network, and a successful `/health` response. Trivy 0.72.0 reported 44 findings (44 HIGH, 0 CRITICAL, 0 MEDIUM, 0 LOW), zero scanner-suppressed findings, and policy outcome `pass` under the existing configured policy. No scanner finding was hidden or policy threshold changed.

The publication decision is `blocked`, accurately reflecting that this candidate was built from a dirty/uncommitted M6 worktree. The canonical release decision is `conditional_pass` and retains its approval conditions. No ECR URL or published digest is fabricated. The ordinary `make supply-chain-full` path builds once; after the candidate was built, this correction pass used `SUPPLY_CHAIN_REUSE_EXISTING=1` for `appsec-full` and `supply-chain-full`. That mode inspects and reuses the recorded image, refreshes its SBOM and scan, recomputes provenance/release links, and verifies checksums without rebuilding. Both targets passed. `make verify-supply-chain-evidence`, `make verify-findings-evidence`, `make verify-release-evidence`, AppSec evidence verification, lifecycle regeneration, consolidated evidence, integration, and portfolio evidence all passed.

The refreshed Trivy database changed the canonical finding set from the previous snapshot (45 findings) to 69. Fourteen tests were coupled to the old scan-derived and downstream counts. They now reconcile outputs against generated source/canonical/lifecycle/export datasets, while the deduplicator's merge semantics are tested with a fixed synthetic same-CVE fixture. Exact assertions for policy-controlled exception counts, risk-accepted records, lifecycle transitions, threat count, requirements, and coverage controls remain. The corrected suite passes: 309 tests, 85.27% coverage. `make final-validation` passed.

## Validation commands

| Check | Intended evidence |
| --- | --- |
| `make format format-check lint type-check test test-coverage quality` | Python implementation, contracts and regression tests |
| `make container-build` | One Buildx build and captured manifest digest |
| `make container-inspect` | Metadata for that already-built candidate; no rebuild |
| `make container-sbom container-scan` | Trivy outputs for the same local image |
| `make supply-chain-evidence verify-supply-chain-evidence publication-decision` | Canonical AppSec/findings/release links, schema/checksum verification and explicit decision |
| `make supply-chain-full` / `make appsec-full` | Full source assurance then one image build, scan and release decision; use `SUPPLY_CHAIN_REUSE_EXISTING=1` only to re-assure the exact recorded local image without rebuilding |
| `make verify-findings-evidence make verify-release-evidence make evidence-full make integration-full make portfolio-full make final-validation` | Existing governance chain remains valid |

## Real-image execution results

| Check | Result |
| --- | --- |
| Runtime base digest | Pinned to `sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce` |
| Candidate builds | Exactly one successful `linux/amd64` build |
| Candidate digest | `sha256:4cf7c5e4472e227388bb9fed5b87781bc1b8d0833dc699edce96f3116bee28ec` |
| Non-root/read-only runtime | Passed as UID/GID 10001; bounded `/tmp`; `/health` passed |
| Container SBOM | CycloneDX 1.7, 109 components, associated with candidate digest |
| Trivy | 0.72.0; 44 HIGH findings, 0 scanner suppressions; policy `pass`; same candidate digest |
| Release/publication | Release `conditional_pass`; publication `blocked` because source worktree was dirty |
| Publication | No ECR push; `published_digest` remains null |
| Evidence verification | Supply-chain checksums, findings, release and lifecycle evidence verified |
| Test suite | 309 passed; 85.27% coverage |

The workflow does not test federation or push the artifact in this milestone. The explicit publication path remains gated until the M3 ECR output, M5 publisher role and repository variables are configured and publication is intentionally requested from `main`.
