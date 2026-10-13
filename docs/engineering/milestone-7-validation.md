# Milestone 7 readiness validation

The initial state and readiness verdict below are historical M7 evidence. The bootstrap lifecycle correction and diagnostic results at the end supersede their tool/version and live-plan blockers for this specific Stage A dry-run; they do not authorize apply or advance another milestone.

The subsequent [M7 corrective suppression validation](m7-corrective-validation.md) resolves the six AppSec failures by removing two obsolete Trivy suppressions after fresh candidate scanning. All requested gates, including `final-validation`, pass with 309 tests and 85.27% coverage. Release remains `conditional_pass`, publication remains blocked, and the unchanged bootstrap saved plan remains 9 additions / 0 changes / 0 destroys. The earlier failed final-validation result below is retained as historical evidence.

## Initial state and baseline

- `main`, clean worktree, HEAD `361ddad` (`Implement build-once supply-chain pipeline`); M1–M6 documents were present.
- `make quality`: pass when run sequentially; 309 tests, 85.27% coverage. An initial concurrent invocation raced with portfolio writers; sequential rerun passed.
- `make final-validation`: pass sequentially. Baseline-generated tracked reports were restored before M7 edits.
- Terraform 1.15.8 installed, incompatible with required 1.16.5. AWS CLI missing. kubectl 1.32.2, Docker/Buildx 28.3.3 / v0.27.0-desktop.1, GitHub CLI 2.94.0 installed. Docker daemon version 28.3.3 confirmed read-only after sandbox escalation.
- No `AWS_*` environment variables; `~/.aws/config` and `~/.aws/credentials` are absent. AWS identity and region were not established because AWS CLI is missing. No live plan is available.
- GitHub CLI is installed but its configured `Ibraheemolasupogit` token is invalid, so remote GitHub Environment settings could not be inspected. No GitHub settings were changed.
- Terraform examples use placeholder region values; the repository does not select a real primary region (`eu-west-2` occurs only in offline test fixtures).

## Readiness verdict

Offline sources show private nonprod EKS, one NAT, separate exact-subject GitHub publisher/QA/prod roles, CodeBuild disabled until connection ARN input, immutable ECR, and S3 backend examples with encryption/KMS/native lockfiles on distinct nonprod/prod/artifact keys. The new independent bootstrap composition models a private/versioned S3 bucket, KMS encryption and deletion safeguards.

AWS state access must be granted separately to named operator/automation roles: scope `s3:ListBucket` to the state bucket and approved key prefixes; `s3:GetObject`/`s3:PutObject` to the selected state object; and `s3:GetObject`/`s3:PutObject`/`s3:DeleteObject` to its `.tflock` object. Scope KMS `Encrypt`, `Decrypt`, `GenerateDataKey`, and `DescribeKey` to the state key and its approved use. No state role/policy is created by bootstrap because account role ownership and principal ARNs are external inputs.

This operator setup is **not ready for Stage A or a live plan**: install approved Terraform 1.16.5 and AWS CLI, authenticate through approved short-lived SSO/federation, select account/region/cost ceiling, choose approved bucket name/owner tags, and reauthenticate `gh` before GitHub settings can be checked. No resource count or plan estimate is invented. CodeBuild also needs an externally authorized repository-scoped CodeConnections GitHub App connection; no PAT/secret is requested.

Final local results: format, format-check, lint, type-check, test (309 passed), test-coverage/quality (309 passed, 85.27%), infrastructure-test (33 passed), Terraform fmt-check, Checkov (512 passed, 0 failed, 48 skipped, 147 resources), findings/release/lifecycle/consolidated/integration/portfolio evidence verification all pass. Terraform init/validate/test and bootstrap validation are blocked by local Terraform 1.15.8 versus exact 1.16.5; the first sandbox attempt also had registry DNS failure. Backend-disabled init succeeded for legacy roots only. AWS readiness and plan guards correctly report blockers. `final-validation` result is recorded in the completion report. `init -backend=false` and mock-provider tests do not constitute a live cloud plan.

## Bootstrap local-state lifecycle correction — 2026-10-13

Confirmed defect: bootstrap `versions.tf` declared an active `backend "s3" {}` before the state bucket existed. `init -backend=false` and `validate` succeeded without initializing that backend, but a normal saved plan then failed with **Backend initialization required**. The initial bootstrap root now has no backend declaration and uses Terraform's default local state. The S3 declaration lives in inactive `backend.tf.example`, which Terraform does not load.

After a separately reviewed bootstrap apply creates S3/KMS, populate ignored `backend.hcl` from `backend.hcl.example` using approved outputs, activate `backend.tf.example` as ignored `backend.tf`, and run `terraform init -migrate-state -backend-config=backend.hcl`. Terraform copies protected local bootstrap state to remote `bootstrap/terraform.tfstate`, with KMS encryption and native S3 locking (`use_lockfile = true`). Keep the live backend files for subsequent operations. Migration was documented only, not executed. See the [Stage A runbook](../runbooks/nonprod-platform-activation.md).

The diagnostic plan used the existing ignored `terraform.tfvars`: region `eu-west-2`, state bucket `devsecops-tfstate-258675982579-eu-west-2`, `CostCenter = "portfolio"`, and `Owner = "platform-security"`. The current identity is account root; authorization was limited to diagnostic planning and local validation. No apply or AWS resource mutation occurred.

| Check | Result |
| --- | --- |
| `terraform version` | Terraform 1.16.5, darwin_arm64 |
| Bootstrap `init -reconfigure` | Passed; initial local backend, no S3 bucket prerequisite |
| Bootstrap `validate` | Passed |
| Bootstrap `plan -var-file=terraform.tfvars -out=bootstrap.tfplan` | Passed: **9 to add, 0 to change, 0 to destroy** |
| Bootstrap `show bootstrap.tfplan` | Passed; no replacements or destroys |
| Saved plan | `infrastructure/terraform/bootstrap/bootstrap.tfplan` (local/ignored) |
| `make terraform-bootstrap-validate` | Passed; 1 mock-provider plan test |
| `make terraform-test` | Passed; 23 mock-provider plan runs, 0 failures |
| `make infrastructure-test` | Passed; 37 tests, including 4 new lifecycle regressions |
| `make checkov-scan` | 512 passed, 0 failed, 48 skipped; 147 resources, 0 parsing errors; online guidelines lookup unavailable |
| `make final-validation` | Failed in `test-coverage`: 303 passed, 6 failed; 84.48% coverage below 85% |
| `git diff --check` | Passed |
| `git status --short` | Only bootstrap lifecycle configuration, tests, and documentation changes; no live artifacts |

The final-validation failures are outside this backend fix: active Trivy suppressions `SUP-TRIVY-PERL-BASE-CRITICAL-001` and `SUP-TRIVY-PERL-BASE-CRITICAL-002` expired on 2026-10-12. Suppression validation raises `active suppression is expired` in six AppSec tests. The suppression policy and dates were not changed. Final-validation did not complete its remaining gates; this dry-run is not a full assurance pass.

Exact planned managed resource types, one of each:

- `aws_kms_alias`
- `aws_kms_key`
- `aws_s3_bucket`
- `aws_s3_bucket_lifecycle_configuration`
- `aws_s3_bucket_ownership_controls`
- `aws_s3_bucket_policy`
- `aws_s3_bucket_public_access_block`
- `aws_s3_bucket_server_side_encryption_configuration`
- `aws_s3_bucket_versioning`

Regression coverage checks the absence of an initial active backend, ignored live artifacts, credential-free Terraform/examples, and the documented post-apply migration order/native locking. A fresh temporary root runs normal local `init`, `validate`, and a targeted bucket-creation saved plan without AWS credentials or an existing bucket; a full mock-provider bootstrap plan checks the composition. The actual untargeted diagnostic plan above used the real approved local values. Initial sandbox DNS/provider-handshake failures were retried with permission; successful results are recorded above.

`terraform.tfvars`, `backend.hcl`, activated `backend.tf`, `*.tfplan`, `terraform.tfstate`, and `terraform.tfstate.*` are ignored and absent from Git's index; examples remain eligible for version control. No credentials were added. No Terraform apply/destroy, migration, IAM creation, ECR push, Kubernetes deployment, M8 work, commit, or push occurred. Generated report changes from validation were restored to keep the patch scoped to this defect.
