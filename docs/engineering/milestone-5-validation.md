# Milestone 5 validation record

## Baseline

Started on clean `main` at M4 commit `70919b4` (`Implement secure Kubernetes workload model`). M1–M4 documentation was present. Baseline generators changed only tracked `outputs/` and `reports/`; those validation-only changes were restored before implementation.

| Check | Baseline result |
| --- | --- |
| `make quality` | pass; 267 tests, 5 warnings, 85.86% coverage; 174 mypy source files clean; threat model 31 threats / 66 requirements |
| `make terraform-fmt-check` | pass |
| `make terraform-init` | initial installed Terraform 1.15.8 could not satisfy M3's exact 1.16.5 constraint. Downloaded the pinned 1.16.5 binary into `/tmp` for offline-safe validation; first registry request failed in sandbox, approved network retry initialized all five roots using backend=false |
| `make terraform-validate` | pass with Terraform 1.16.5 for all five roots; no AWS plan/API calls |
| `make terraform-test` | pass; 15 mock-provider Terraform test runs passed across artifacts, nonprod/prod, EKS, networking and ECR modules |
| `make infrastructure-test` | pass; 15 tests |
| `make checkov-scan` | pass; 399 passed / 0 failed / 42 skipped / 0 parsing errors. Optional Prisma Cloud guidelines lookup failed DNS; local scan completed |
| `make verify-infrastructure-evidence` | pass |
| `make final-validation` | pass; quality, evidence, integration and portfolio generation/verification passed |
| `git diff --check` / `git status --short` | clean after restoring baseline-generated `outputs/` and `reports/` |

## M5 result

| Check | M5 result |
| --- | --- |
| `make format`, `make format-check`, `make lint`, `make type-check` | pass; 194 Python files formatted, Ruff clean, mypy 174 source files clean |
| `make test` | pass; 269 tests, 5 existing framework/JWT warnings |
| `make test-coverage` | pass; 85.86% total coverage (85% minimum) |
| `make quality` | pass after regenerating deterministic threat-model and infrastructure source evidence |
| `make terraform-fmt-check`, `make terraform-init`, `make terraform-validate` | pass with Terraform 1.16.5; backend disabled; all five environment/root compositions validated |
| `make terraform-test` | pass; 22 mock-provider test runs across artifacts, nonprod/prod, and six focused modules |
| `make infrastructure-test` | pass; 24 tests |
| `make checkov-scan` | pass; Terraform: 484 passed, 0 failed, 42 skipped, 0 parsing errors. The optional Prisma guidelines request failed due unavailable DNS; local Checkov ran successfully |
| `make k8s-full` | pass; QA/prod each render 8 workload resources, namespace roots each render 1 resource, RBAC roots each render 2 resources; Kubernetes Checkov: 208 passed, 0 failed/skipped; 12 parsed-manifest tests passed |
| `make verify-threat-model-evidence`, `make verify-infrastructure-evidence` | pass after regenerating for the three new CI controls and M5 Terraform source inventory |
| `make final-validation` | pass; quality, assurance evidence, integration contract and portfolio validation passed |
| `git diff --check` | pass; no whitespace errors |

The threat model now validates 31 threats and 69 requirements. The installed system Terraform was 1.15.8, below the repository's exact pin; validation used Terraform 1.16.5 from `/tmp`. The M3 roots and new modules use AWS provider 6.68.0; the retained ECS reference root continues using its existing AWS provider 5.100.0 lock. No AWS-backed plan, apply, OIDC federation call, CodeBuild run, image push or Kubernetes API call was made.
