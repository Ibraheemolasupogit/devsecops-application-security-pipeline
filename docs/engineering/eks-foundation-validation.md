# EKS foundation validation — Milestone 3

Run began 2026-10-11 and completed 2026-10-12 on Darwin ARM64, Python 3.12.8, Terraform 1.16.5, with the repository .venv on PATH. Initial branch main tracked origin/main, HEAD `0e59bfc` (Rationalise repository for EKS delivery); worktree clean. Milestone 1 commit `682ec76` and M1/M2 documents present. Logs are local at `/tmp/eks-m3-validation/` and not portable evidence; summaries below record the observed results. No AWS identity/credentials were queried and no live AWS plan/apply was run.

## Baseline before changes

| Command | Result |
| --- | --- |
| make quality | exit 0; 255 tests, 6 warnings, 85.84% coverage; 10 infrastructure tests; auth 7/API 19 passed |
| make terraform-fmt-check | exit 0 |
| make terraform-init | initial exit 2: provider registry DNS lookup `registry.terraform.io: no such host` in sandbox; approved registry-access retry exit 0 for both ECS environments |
| make terraform-validate | initial exit 2 at registry init for the same DNS restriction; approved registry-access retry exit 0 for both ECS environments |
| make terraform-test | exit 0; **0 passed, 0 failed**, no Terraform assertions existed |
| make infrastructure-test | exit 0; 10 passed |
| make checkov-scan | exit 0; native 296 passed / 0 failed / 27 skipped / 0 parsing errors; 78 resources, Checkov 3.2.281 |
| make verify-infrastructure-evidence | exit 0 |
| git diff --check / git status --short | exit 0; tests regenerated tracked evidence/reports from the initially clean checkout; baseline side effects restored before authoring |

Baseline scan/verification reused existing reference evidence outside Checkov; none establishes a deployment. Terraform retry used backend=false, no credentials and no AWS API calls. Existing ECS lockfiles retained AWS provider 5.100.0.

## Implementation verification

| Command | Result |
| --- | --- |
| make format | exit 0; 191 Python files formatted; no runtime semantics changed |
| make format-check | exit 0 |
| make lint | exit 0 |
| make type-check | exit 0; no issues in 173 source files |
| make test | exit 0; 257 passed, 6 warnings |
| make quality | exit 0; 257 passed, 85.86% coverage; auth 7/API 19/infrastructure 15 passed; evidence verifiers passed |
| make terraform-fmt-check | exit 0 |
| make terraform-init | exit 0; backend-disabled ECS dev/prod and EKS artifacts/nonprod/prod roots |
| make terraform-validate | exit 0; all five compositions valid |
| make terraform-test | exit 0; **15 passed, 0 failed** across six mock-provider suites; all commands are plan simulations, no live providers/applies |
| make infrastructure-test | exit 0; **15 passed** (10 retained ECS, 5 EKS boundary tests) |
| make checkov-scan | exit 0; native **399 passed / 0 failed / 42 skipped / 0 parsing errors**, 125 resources |
| make verify-infrastructure-evidence | exit 0; source inventory/checksum checks now reject changed Terraform inputs |
| Direct nonprod init -backend=false / validate | both exit 0 |
| Direct prod init -backend=false / validate | both exit 0 |
| providers lock, Linux AMD64 and Darwin ARM64 | signed HashiCorp checksums fetched for all three new root stacks; copied identical portable locks to the three standalone module test roots |

An intermediate mock run failed because mock IAM policy JSON and nullable absent security-group CIDR attributes were handled incorrectly in test fixtures/assertions. These were corrected; production controls were not relaxed. Checkov's initial foundation scan flagged five checks: version-table age, KMS root delegation, and operational retention. Documented resource-local exceptions explain each decision in source and architecture/cost documents. No global skip or severity policy change was made.

The scanner wrapper's pre-existing `--soft-fail` remains: its exit code alone is insufficient. The native failed/parsing counts above were inspected separately and are zero. Scanner upgrade/policy enforcement remains later pipeline work. Checkov counts are its source graph inventory, not an AWS inventory; shared module expansion/deduplication can differ from actual per-environment resource count. Both environment roots also undergo direct validation and mock plan tests.

## Evidence boundary and limitations

Canonical infrastructure and AppSec evidence is regenerated for the authored HCL/new Checkov raw result. Source integrity verification now fails on added/removed/changed Terraform inputs; tests exercise tampered input checksums and missing inventory. The historical ECS `compute` field is retained for compatibility, explicitly labelled reference, with a separate primary EKS inventory object. Fixed reference timestamps remain fixtures; this document records the real local run rather than inventing live deployment evidence. Dependent findings/release/lifecycle/consolidated/integration/portfolio bundles are refreshed through their existing generators to preserve lineage; no scanner or release policy is weakened.

No full AppSec image build, dynamic testing, live AWS plan, Kubernetes apply or application rollout is required/run in M3. Docker daemon availability is irrelevant to offline HCL validation. The six existing warnings include negative JWT key fixtures/deprecations; coverage stays above the unchanged 85% threshold. Registry/provider downloads required approved network access; AWS CLI/account credentials are not needed for these checks.

Offline checks cannot establish quotas, approved add-on availability, node AMI compatibility, actual KMS grants/SCPs, cross-account ECR pull, private operator connectivity, AZ node distribution, network-policy enforcement or HA. Defaults are small portfolio foundations, not measured production sizing. Backend bootstrap and production account/budget/log-retention/CloudTrail ownership remain prerequisites before any separately authorised deployment.

## Final file inventory

All new Terraform/source/test/config paths below are intentional. Local .terraform caches and coverage files remain ignored; no files are deleted. Root and standalone-test provider locks are intentionally retained. .gitignore adds only the operator-specific EKS backend.hcl pattern; .example files remain visible.

Created (61):

```text
docs/architecture/eks-infrastructure.md
docs/engineering/eks-cost-controls.md
docs/engineering/eks-foundation-validation.md
infrastructure/terraform/artifacts/.terraform.lock.hcl
infrastructure/terraform/artifacts/backend.hcl.example
infrastructure/terraform/artifacts/main.tf
infrastructure/terraform/artifacts/tests/supply_chain.tftest.hcl
infrastructure/terraform/artifacts/versions.tf
infrastructure/terraform/environments/nonprod/.terraform.lock.hcl
infrastructure/terraform/environments/nonprod/backend.hcl.example
infrastructure/terraform/environments/nonprod/main.tf
infrastructure/terraform/environments/nonprod/outputs.tf
infrastructure/terraform/environments/nonprod/providers.tf
infrastructure/terraform/environments/nonprod/terraform.tfvars.example
infrastructure/terraform/environments/nonprod/tests/foundation.tftest.hcl
infrastructure/terraform/environments/nonprod/variables.tf
infrastructure/terraform/environments/nonprod/versions.tf
infrastructure/terraform/environments/prod/.terraform.lock.hcl
infrastructure/terraform/environments/prod/backend.hcl.example
infrastructure/terraform/environments/prod/main.tf
infrastructure/terraform/environments/prod/outputs.tf
infrastructure/terraform/environments/prod/providers.tf
infrastructure/terraform/environments/prod/terraform.tfvars.example
infrastructure/terraform/environments/prod/tests/foundation.tftest.hcl
infrastructure/terraform/environments/prod/variables.tf
infrastructure/terraform/environments/prod/versions.tf
infrastructure/terraform/modules/ecr/.terraform.lock.hcl
infrastructure/terraform/modules/ecr/main.tf
infrastructure/terraform/modules/ecr/outputs.tf
infrastructure/terraform/modules/ecr/tests/immutability.tftest.hcl
infrastructure/terraform/modules/ecr/variables.tf
infrastructure/terraform/modules/ecr/versions.tf
infrastructure/terraform/modules/eks/.terraform.lock.hcl
infrastructure/terraform/modules/eks/main.tf
infrastructure/terraform/modules/eks/outputs.tf
infrastructure/terraform/modules/eks/tests/security.tftest.hcl
infrastructure/terraform/modules/eks/variables.tf
infrastructure/terraform/modules/eks/versions.tf
infrastructure/terraform/modules/iam/main.tf
infrastructure/terraform/modules/iam/outputs.tf
infrastructure/terraform/modules/iam/variables.tf
infrastructure/terraform/modules/iam/versions.tf
infrastructure/terraform/modules/kms/main.tf
infrastructure/terraform/modules/kms/outputs.tf
infrastructure/terraform/modules/kms/variables.tf
infrastructure/terraform/modules/kms/versions.tf
infrastructure/terraform/modules/logging/main.tf
infrastructure/terraform/modules/logging/outputs.tf
infrastructure/terraform/modules/logging/variables.tf
infrastructure/terraform/modules/logging/versions.tf
infrastructure/terraform/modules/networking/.terraform.lock.hcl
infrastructure/terraform/modules/networking/main.tf
infrastructure/terraform/modules/networking/outputs.tf
infrastructure/terraform/modules/networking/tests/routing.tftest.hcl
infrastructure/terraform/modules/networking/variables.tf
infrastructure/terraform/modules/networking/versions.tf
infrastructure/terraform/modules/platform/main.tf
infrastructure/terraform/modules/platform/outputs.tf
infrastructure/terraform/modules/platform/variables.tf
infrastructure/terraform/modules/platform/versions.tf
infrastructure/tests/test_eks_foundation.py
```

Modified (48):

```text
.github/workflows/ci.yml
.github/workflows/terraform-security.yml
.gitignore
infrastructure/README.md
outputs/portfolio/evidence-index.json
outputs/portfolio/portfolio-manifest.json
outputs/portfolio/portfolio-summary.json
outputs/portfolio/report-index.json
outputs/portfolio/reports/final-architecture-report.md
outputs/portfolio/reports/final-evidence-report.md
outputs/portfolio/reports/final-project-report.md
outputs/portfolio/reports/final-security-assurance-report.md
outputs/portfolio/reports/final-testing-report.md
outputs/security/appsec/evidence-manifest.json
outputs/security/appsec/iac-scan-summary.json
outputs/security/appsec/raw/checkov.json
outputs/security/evidence/consolidated-evidence.json
outputs/security/evidence/evidence-domain-summary.json
outputs/security/evidence/evidence-manifest.json
outputs/security/evidence/portfolio-security-summary.json
outputs/security/findings/evidence-manifest.json
outputs/security/infrastructure/architecture-inventory.json
outputs/security/infrastructure/evidence-manifest.json
outputs/security/integration/checksums.sha256
outputs/security/integration/integration-manifest.json
outputs/security/portfolio/evidence-index.json
outputs/security/portfolio/portfolio-manifest.json
outputs/security/portfolio/portfolio-metrics.json
outputs/security/portfolio/portfolio-summary.json
outputs/security/portfolio/report-index.json
outputs/security/release/evidence-manifest.json
reports/portfolio/final-architecture-report.md
reports/portfolio/final-evidence-report.md
reports/portfolio/final-limitations-report.md
reports/portfolio/final-portfolio-readiness-report.md
reports/portfolio/final-project-report.md
reports/portfolio/final-security-assurance-report.md
reports/portfolio/final-testing-report.md
reports/security/aws-architecture-report.md
reports/security/iac-security-report.md
reports/security/portfolio-assurance-report.md
reports/security/product-security-report.md
reports/security/security-evidence-report.md
reports/security/terraform-security-report.md
scripts/terraform_local.py
src/genomic_research_access_api/security/infrastructure/evidence.py
src/genomic_research_access_api/security/infrastructure/report.py
tests/security/test_infrastructure_evidence.py
```

Dependent findings/release/lifecycle/enablement/Champions/consolidated/integration/portfolio generation completed with exit 0; their final evidence verifiers passed. Dynamic scanner outputs were not regenerated. Git diff --check passed; final status contains only the listed intended source/documentation/IaC and derived evidence/report changes, with HEAD still 0e59bfc. No apply, AWS resource creation, deployment, application manifests, commit or push occurred.

## Review correction validation — 2026-10-12

The M3 review correction selects Kubernetes 1.36 (AWS standard-support end 2027-08-02), exact Terraform 1.16.5 and exact AWS provider 6.68.0. Terraform 1.16.5 is an official stable patch; provider 6.68.0 is a signed stable release. Reviewed AWS provider releases 6.67/6.68: their notes contain no changes to EKS cluster/node group/add-on/access entries, VPC, IAM, KMS or ECR resources in this foundation. Upgrading from 1.15.8/6.21.0 produced no compatibility issue in the requested offline validations. Locks are regenerated for Linux AMD64 and Darwin ARM64.

Private API connectivity is explicitly separated from identity: protected GitHub job on a single-job CodeBuild-hosted runner in the target VPC, then GitHub OIDC token to AWS STS for a narrow environment role, and independent VPC routing/private DNS/security group access to TCP 443 on the private EKS endpoint. The CodeBuild service role stays separate and minimal. CodeBuild's GitHub App/webhook credential is a separate control. M5 will implement this; no runner is introduced in this correction.

Official release references reviewed: [Terraform 1.16.5](https://github.com/hashicorp/terraform/releases/tag/v1.16.5), [AWS provider 6.68.0](https://github.com/hashicorp/terraform-provider-aws/releases/tag/v6.68.0), [AWS provider 6.67.0](https://github.com/hashicorp/terraform-provider-aws/releases/tag/v6.67.0), [EKS version lifecycle](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html), [CodeBuild-hosted GitHub Actions runners](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner-overview.html).

Correction-pass validation:

| Check | Result |
| --- | --- |
| `make format` | exit 0; 191 files already formatted |
| `make format-check lint type-check test quality` | final `make quality` exit 0; 257 tests passed, 85.86% coverage; 173 source files type-checked; lint/format/evidence verifiers passed |
| `make terraform-fmt-check terraform-init terraform-validate terraform-test` | exit 0; all five compositions initialized and validated with backend disabled; 15 mock-provider Terraform test cases passed |
| Direct artifacts, nonprod, prod, shared `platform` init/validate | all exit 0 with `-backend=false`; no AWS plan or API calls |
| `make infrastructure-test` | exit 0; 15 passed |
| `make checkov-scan` | exit 0; 397 passed / 0 failed / 42 skipped / 0 parsing errors; 125 resources; Checkov 3.2.281 |
| `make verify-infrastructure-evidence` | exit 0 after regenerating version/default and source-integrity evidence |
| `git diff --check` | exit 0 |

The Checkov CLI's optional Prisma Cloud guideline lookup emitted a network/TLS warning; its local Terraform scan completed and the native summary above contains zero failed checks and parsing errors. No policy or exception scope was changed to address the warning. A first `make quality` attempt correctly caught stale source-checksum evidence after the version edit; the infrastructure evidence/report and dependent AppSec evidence/report were regenerated, and the final quality and verifier runs passed. The direct Terraform validations needed execution outside the sandbox because macOS denied the provider's local Unix socket within it; this did not involve AWS credentials, state or network API calls. The standalone `platform` module lockfile was generated on its direct validation; every EKS provider lock resolves exactly 6.68.0 with signed checksums.
