# Milestone 2 Validation Record

EKS evolution, 2026-10-11. No cloud creation/deployment/commit/push. User-authorised starting cleanup touched only generated evidence/reports and numbered local copies. Clean baseline confirmed: git status --short --branch printed only `## main...origin/main`; HEAD `682ec76 Define EKS DevSecOps target architecture`. All five M1 documents present; no applicable AGENTS.md found.

## Baseline

| Check | Exact result |
| --- | --- |
| make quality | exit 0; 254 passed, 5 warnings, 85.82% coverage; auth 7 passed/12 deselected, API 19 passed, infrastructure 10 passed |
| make appsec-full | exit 2 at dependency-audit; temporary pip environment upgrade failed under sandbox networking |
| make appsec-full network-enabled retry | exit 2 at dependency-audit; scanner exit 1, 14 advisories in PyJWT 2.13.0 |
| docker info network/socket-enabled check | exit 1; Cannot connect to the Docker daemon at unix:///Users/privilege/.docker/run/docker.sock. Is the docker daemon running? |
| make dynamic-full | Not run: Docker daemon unavailable; required conditional prerequisite not met |
| make final-validation | exit 0; quality/evidence/integration/portfolio passed, 254 tests, 85.82% coverage |
| git diff --check | exit 0 |
| git status --short | exit 0; baseline regenerated evidence/package/reports and deleted the five portfolio duplicate files |

Restored baseline generation side effects before applying reviewed cleanup; nine audited tracked removals were then intentional. Historical M1 audit remains unchanged. Logs are retained locally in /tmp/eks-m2, not a committed portable artifact or substitute for this record/native evidence.

## Dependency and scanner verification

PyJWT 2.15.1 installed in .venv, editable package metadata refreshed; pip check exit 0, no broken requirements. Initial no-build-isolation editable refresh failed (setuptools.build_meta unavailable); declared isolated-backend retry succeeded. Focused JWT/API/dynamic boundary suite exit 0: 27 passed, 5 warnings. Project-scoped make dependency-audit exit 0: No known vulnerabilities found.

Network-enabled make appsec-full exit 2 at container-build-security: Docker daemon unavailable. Gitleaks, Semgrep and Bandit completed; runtime dependency audit passed; CycloneDX SBOM and validation completed; Checkov local checks completed with 296 passed, 0 failed, 27 existing skips, 0 parsing errors. Checkov emitted SSL certificate verification errors while fetching optional PrismaCloud guideline metadata; no TLS verification bypass was introduced, and its native result matched the previous canonical JSON. Docker image build failed; Trivy and automatic terminal evidence/report stages were not reached.

Domain evidence refresh is explicit after these stages, preserving unchanged historical Trivy and dynamic raw results. Its verification validates the reference model, not fresh full image/dynamic assurance. No suppression, scanner skip or severity/coverage/policy relaxation was added. See [dependency hygiene](dependency-hygiene.md) for exact advisory aliases and fix-version caveat.

## Validation environment and limitations

Baseline used the system Python 3.12.8. All post-change Make commands use the repository .venv/bin on PATH, also Python 3.12.8, to exercise the upgraded pin. Most CI jobs use 3.11 and some 3.12; local results do not establish complete cross-version CI parity. Terraform installed 1.15.8; existing CI pins 1.8.5. Docker CLI 28.3.3 exists, server unavailable. AWS CLI absent; kubectl/GitHub CLI present. No cloud tool installed/configured.

Warnings include synthetic short-HMAC negative tests and Starlette/httpx/422 deprecations. Preserve negative tests; do not suppress warnings to claim compatibility. Direct runtime graph was audited; scanner-tool dependencies are a separate environment.

## Post-change required checks

| Command | Result |
| --- | --- |
| make format | exit 0; one test file reformatted, 189 unchanged; lint fixes made no policy changes |
| make format-check | exit 0; 190 files formatted |
| make lint | exit 0 |
| make type-check | exit 0; 173 source files, no issues |
| make test | exit 0; 255 passed, 6 warnings |
| make test-coverage | exit 0; 255 passed, 6 warnings; 85.84%, threshold unchanged at 85% |
| make quality | exit 0; 255 passed, 6 warnings; 85.84%; auth/API/infrastructure checks passed |
| make dependency-audit | exit 0; no known vulnerabilities in resolved upgraded runtime graph |
| make appsec-full | exit 2 at container-build-security; preceding source/SCA/SBOM/Checkov stages completed; Docker daemon unavailable |
| make dynamic-full | Not run: Docker daemon unavailable; focused in-process dynamic boundary tests passed |

Generated evidence is retained only where needed for a consistent reviewed dependency/artifact refresh; local-only working files remain ignored. Domain refresh (AppSec, findings, release/lifecycle, enablement/Champions verification, consolidated evidence, integration, portfolio) exited 0. No canonical finding IDs, lifecycle states or exception policies were removed. Exact final-validation and final diff/status results follow after completion.

Final make final-validation: exit 0; 255 tests passed, 6 warnings, 85.84% coverage; quality and required evidence/integration/portfolio verification passed. git diff --check: exit 0. git status --short --branch: main remains at 682ec76 with only the intended M2 changes, not a clean worktree because nothing is committed. Final local documentation links and scoped ignore-pattern checks passed.

Structural review confirmed no workflow YAML, Terraform HCL/provider lock, scanner/release/lifecycle policy, fixtures, authentication, services or repository runtime code changed. Canonical findings, vulnerability-register, exceptions and release-gate-decision payloads are byte-identical to HEAD. Only security evidence tooling changed in src (fallback SBOM); a regression test was added. Refreshed manifests/native audit/SBOM, consolidated provenance, environment prerequisites and portfolio indexes/packages explain generated-file changes. Existing controlled January timestamps and not_deployed status remain fixture boundaries. Full AppSec/dynamic freshness is not claimed.

## Recommended M3 scope

Create a separate EKS foundation composition with documented owners and separate environment state: pinned Terraform/provider versions, remote-state/bootstrap configuration, VPC/subnets/IP capacity/private endpoints, EKS control plane/managed nodes, cluster access boundaries and role scaffolding, encryption/control-plane logs, immutable ECR foundation, cost/retention/destroy boundaries. Require fmt/init -backend=false/validate, policy and trust-negative tests, then an authenticated reviewed plan/cost assessment only with authorised account access. Bootstrap/apply must be explicitly authorised separately; no cloud mutation is implied by repository implementation. Defer app packaging/persistence to M4, live OIDC operational proof to M5, build/promotion to M6+, and controllers/deployment to their later milestones. Preserve ECS paths/evidence as reference.

## Exact final file inventory

M = modified; D = deleted; ?? = newly created. This inventory includes intentional generated assurance refresh, not broad cleanup.

```text
 D ".coverage 2"
 D ".coverage 3"
 D ".coverage 4"
 M .gitignore
 M README.md
 M docs/README.md
 M docs/security/dependency-security.md
 M infrastructure/README.md
 D "outputs/portfolio/README 2.md"
 M outputs/portfolio/docs/README.md
 D "outputs/portfolio/evidence-index 2.json"
 M outputs/portfolio/evidence-index.json
 D "outputs/portfolio/portfolio-manifest 2.json"
 M outputs/portfolio/portfolio-manifest.json
 D "outputs/portfolio/portfolio-summary 2.json"
 M outputs/portfolio/portfolio-summary.json
 D "outputs/portfolio/report-index 2.json"
 M outputs/portfolio/report-index.json
 M outputs/portfolio/reports/final-architecture-report.md
 M outputs/portfolio/reports/final-evidence-report.md
 M outputs/portfolio/reports/final-project-report.md
 M outputs/portfolio/reports/final-security-assurance-report.md
 M outputs/portfolio/reports/final-testing-report.md
 M outputs/security/appsec/evidence-manifest.json
 M outputs/security/appsec/raw/bandit.json
 D "outputs/security/appsec/raw/gitleaks 2.json"
 M outputs/security/appsec/raw/pip-audit.json
 M outputs/security/appsec/sbom.cdx.json
 M outputs/security/developer-enablement/enablement-summary.json
 M outputs/security/developer-enablement/evidence-manifest.json
 M outputs/security/developer-enablement/prerequisite-check-summary.json
 M outputs/security/evidence/consolidated-evidence.json
 M outputs/security/evidence/evidence-domain-summary.json
 M outputs/security/evidence/evidence-manifest.json
 M outputs/security/evidence/portfolio-security-summary.json
 M outputs/security/findings/evidence-manifest.json
 M outputs/security/integration/checksums.sha256
 M outputs/security/integration/integration-manifest.json
 M outputs/security/portfolio/evidence-index.json
 M outputs/security/portfolio/portfolio-manifest.json
 M outputs/security/portfolio/portfolio-metrics.json
 M outputs/security/portfolio/portfolio-summary.json
 M outputs/security/portfolio/report-index.json
 M outputs/security/release/evidence-manifest.json
 M pyproject.toml
 M reports/portfolio/final-architecture-report.md
 M reports/portfolio/final-evidence-report.md
 M reports/portfolio/final-limitations-report.md
 M reports/portfolio/final-portfolio-readiness-report.md
 M reports/portfolio/final-project-report.md
 M reports/portfolio/final-security-assurance-report.md
 M reports/portfolio/final-testing-report.md
 M reports/security/portfolio-assurance-report.md
 M reports/security/product-security-report.md
 M reports/security/security-evidence-report.md
 M reports/security/security-tooling-readiness-report.md
 M src/genomic_research_access_api/security/appsec/evidence.py
 M tests/security/test_appsec_pipeline.py
?? docs/engineering/dependency-hygiene.md
?? docs/engineering/eks-prerequisites.md
?? docs/engineering/milestone-2-validation.md
?? docs/engineering/repository-artifact-policy.md
?? docs/engineering/workflow-rationalisation-plan.md
```
