# Milestone 4 validation record

## Baseline

Baseline was run from clean branch `main` at M3 commit `c82b973` (`Implement EKS Terraform foundation`). M1–M3 architecture/engineering documents were present.

| Command/check | Baseline result |
| --- | --- |
| `make quality` | exit 0; 257 passed, 5 warnings; 85.86% coverage; type, lint, format, threat-model and evidence checks passed |
| `make appsec-full` | exit 2 at `container-build-security`: Docker CLI 28.3.3 was installed, but Docker Desktop daemon socket was unavailable. The initial sandboxed dependency-audit attempt could not upgrade pip in pip-audit's temporary venv; escalated retry reported no known dependency vulnerabilities. Local Checkov reported 399 passed / 0 failed / 42 skipped / 0 parsing errors. |
| `make final-validation` | exit 0; quality, evidence generation/verification, integration and portfolio checks passed |
| `docker info` | unavailable: `permission denied` connecting to `unix:///Users/privilege/.docker/run/docker.sock`; no server running/accessible |
| `make dynamic-full` | not run because Docker daemon is unavailable |
| `git diff --check` / `git status --short` | clean at baseline; baseline-generated changes under `outputs/` and `reports/` were restored before implementation |

Baseline security warnings include existing Starlette deprecation and short negative-test JWT key warnings. No thresholds or policies were changed.

## Workload model checks

Final M4 validation results are recorded after the implementation checks below. All rendering and policy checks are offline; no live EKS connection is configured.

| Command/check | Result |
| --- | --- |
| `make format`, `make format-check`, `make lint`, `make type-check` | pass; 193 files formatted, Ruff clean, mypy clean (174 source files) |
| `make test`, `make test-coverage`, `make quality` | pass; 267 passed, 5 existing warnings, 85.86% coverage; quality also passed threat-model, security-evidence and infrastructure checks |
| `make k8s-render`, `make k8s-validate`, `make k8s-security`, `make k8s-test`, `make k8s-full` | pass; QA and production each render/validate 9 unique resources; Checkov Kubernetes 186 passed / 0 failed / 0 skipped; 10 workload tests passed |
| `make appsec-full` | blocked at `container-build-security` (exit 2): Docker CLI 28.3.3 is installed, but daemon access is denied at `/Users/privilege/.docker/run/docker.sock`. Before that point, pip-audit found no known dependency vulnerabilities, Semgrep found 0 findings across 163 tracked files, and Terraform Checkov reported 399 passed / 0 failed / 42 skipped / 0 parsing errors. The AppSec aggregate evidence stage did not run; partial raw scanner outputs were restored. |
| `make final-validation` | pass; quality plus threat model (31 threats/66 requirements), API security, infrastructure (15 tests), all evidence source verification, consolidated evidence, integration, developer enablement, Champions and portfolio generation/verification |
| `git diff --check` | pass |
| `git status --short --branch` | `main...origin/main` with intended M4 source/docs/manifests and deterministic threat/evidence/report updates; no unexpected temporary numbered artifacts |

## Environment

The available client is kubectl 1.32.2, which embeds Kustomize 5.5.0. No standalone `kustomize` binary was present. Docker daemon access remained unavailable, so image build-under-UID and Docker-backed `make dynamic-full` checks could not run. Checkov's optional Prisma Cloud guidelines lookup also emitted a DNS resolution warning; the local Kubernetes policy scan itself completed successfully without skipped or failed checks. No validation connected to a live cluster.
