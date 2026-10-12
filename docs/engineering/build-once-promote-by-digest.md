# Build once, promote by digest

## Candidate identity

The candidate key is the source repository and full Git commit SHA. The local convenience tag is `genomic-research-access-api:git-<full-commit>` and is never authoritative. Buildx returns a manifest digest (`sha256:<64 lowercase hex>`); metadata also stores Docker's image config ID separately. The Python base image uses its official multi-platform index digest. The ECR registry manifest digest is captured after publication and must equal the locally assured digest before the publication manifest becomes `published_verified`.

The same digest is validated in QA and promoted to production. M7 consumes `outputs/security/supply-chain/release-artifact.json`; M10 must copy/promote or retag the existing ECR artifact by digest, then verify the production reference resolves to that exact digest. Rebuilding for QA or production is prohibited. An auxiliary Git-SHA tag helps discovery only and ECR tag immutability prevents reuse of that tag.

## Build path

Use `make supply-chain-full` for the canonical assurance path. It performs source security checks, CycloneDX application dependency evidence and Checkov, then calls `scripts/container_supply_chain.py full`. The orchestrator builds once with Docker Buildx and a fixed target architecture, inspects the exact local image, creates an actual container SBOM with Trivy, scans the same local tag with Trivy, and links its raw result to the canonical findings and release engine. It fails on command errors, missing/invalid digest, changed inputs, inconsistent SBOM/scan digest, failed release evidence or checksum errors.

The caller can supply explicit operations for diagnostics: `build`, `inspect`, `sbom`, `scan`, `provenance`, `verify`, `publication-manifest`, and `full`. Stage operations after build require the existing artifact and evidence from that same working run; they do not initiate another build. Use `make verify-supply-chain-evidence` to check manifest checksums and cross-evidence references.

CI keeps the candidate in one job from build through optional publish. Normal PR/push runs use `verify`. A manual `publish` mode is accepted only from `main`, with `ENABLE_ECR_PUBLICATION=true`, M3/M5 output variables configured, a successful scan and an unconditional release-policy pass. No protected branch, ECR repository or publisher identity is created by this change. OIDC is exchanged for short-lived STS credentials; the workflow stores no AWS access keys.

## Evidence and decisions

The local build success is separate from security completion and publication approval. A successful build with incomplete assurance is blocked. A dirty source worktree is recorded and blocks publication because the image cannot be attributed to its commit alone. A conditional release result stays conditional and is not published automatically. The container scan contributes through `outputs/security/appsec/raw/trivy.json` into the pre-existing canonical findings model, risk calculation, release policy and required approvals. The new publication eligibility record references the release decision and the canonical Trivy finding IDs; it does not implement another threshold.

`build-metadata.json`, `image-metadata.json`, `sbom-summary.json`, `container-scan-summary.json`, `provenance.json`, `publication-eligibility.json`, `release-artifact.json`, `supply-chain-manifest.json` and `checksums.sha256` are generated together after real image assurance. Never hand-author an image digest or commit fake output after Docker/Trivy is unavailable. Fixed commit timestamps keep candidate evidence replayable; raw scanner databases and tool versions remain part of the scan context.

Transitive Python dependencies are not completely hash-locked. Metadata records those inputs and exact artifact identity; it does not claim a hermetic or bitwise-identical build. A later dependency refresh should resolve that risk without changing the build-once rule.
