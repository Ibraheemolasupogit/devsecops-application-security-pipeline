# Non-production platform activation runbook

This runbook is not authorization to execute. Stage A init/validate/plan may run under explicit diagnostic authorization; apply and migration require separate approval. No Stage A apply or migration has run. Record the approved AWS account, principal, region, cost ceiling, owner, and change window before any stage. Stop if identity, plan, trust, or cost differs from reviewed inputs. Production is excluded from M7.

## Preconditions

- Install approved Terraform 1.16.5 and AWS CLI through the operator's tool-management process; this repository does not install cloud tools.
- Approve one AWS region; validate EKS 1.36, AZs, quotas, add-ons, CodeBuild, KMS and ECR availability.
- Use short-lived organization-approved SSO/federated credentials; never store long-lived access keys.
- Create deployment-specific variable/backend files from approved values, excluded from Git. Bootstrap state begins as a protected local state file until migration.
- Confirm GitHub repository identity, QA Environment protections, CodeConnections owner, budget and alerts.

## Stage A — remote-state bootstrap (approval required)

The initial bootstrap root has **no active backend block**, so Terraform uses local state (`terraform.tfstate`). `backend.tf.example` is an inactive template and is not loaded by Terraform. Keep it inactive for the initial plan/apply: the S3 bucket and KMS key do not exist yet. Do not use `init -backend=false` to bypass an active S3 backend; that allows validation but cannot initialize the backend needed by a normal plan.

**After diagnostic/plan approval only:** copy `terraform.tfvars.example` to ignored `terraform.tfvars` and fill approved values. From `infrastructure/terraform/bootstrap`, run:

```sh
terraform init -reconfigure
terraform validate
terraform plan -var-file=terraform.tfvars -out=bootstrap.tfplan
terraform show bootstrap.tfplan
```

A separate explicit approval is required before `terraform apply bootstrap.tfplan`; never use `-auto-approve`. A successful diagnostic plan does not authorize apply. Protect local state, its backups, and saved plans as sensitive operator artifacts; they and live variable/backend files are excluded from Git.

Expected: one S3 bucket, ownership controls, public-access block, versioning, incomplete-upload lifecycle rule, KMS encryption/key/alias, TLS-only bucket policy. Bucket/key have `prevent_destroy`, and force deletion is false. Before Stage A apply, verify central CloudTrail data-event auditing for the state bucket or add a separately reviewed audit control; this composition does not create its own second logging bucket.

**Post-bootstrap migration, only after the reviewed apply succeeds:** verify the S3/KMS resources exist, private access, encryption/versioning, and restore a prior object version before state migration. Preserve a protected backup of local state. Copy `backend.hcl.example` to ignored `backend.hcl` and fill the approved bucket, region and KMS ARN from bootstrap outputs. Keep `key = "bootstrap/terraform.tfstate"`, `encrypt = true`, and `use_lockfile = true` (native S3 locking). Activate the S3 backend declaration and migrate through Terraform:

```sh
cp backend.tf.example backend.tf
terraform init -migrate-state -backend-config=backend.hcl
```

Review and accept Terraform's state-copy prompt only under migration approval. Do not use `-reconfigure` for this migration, as it does not copy local state. Verify `terraform state list` and the remote `bootstrap/terraform.tfstate` object/version after migration. Retain ignored `backend.tf` and `backend.hcl` for subsequent bootstrap operations; do not remove the active backend and revert to local state. Never move/edit state manually to perform migration. The lifecycle is **local bootstrap state → reviewed bootstrap apply → S3/KMS backend exists → activate S3 backend configuration → `terraform init -migrate-state` → `bootstrap/terraform.tfstate` stored remotely**.

Put the same approved bucket/KMS values in each environment's ignored backend file; migrate only nonprod and artifacts states after separate state review. Production's configuration remains untouched during M7. **Rollback:** preserve state; restore versions only under lock with reviewed procedure. Do not destroy bootstrap. **Cost:** S3 versions/requests and KMS.

## Stage B — nonprod platform Terraform (separate approval required)

Use only `infrastructure/terraform/environments/nonprod`, approved backend and nonprod variables. Create and inspect a saved plan; require expected account, region/state key, additions only, no replacement/destroy, reviewed exact inventory and cost. A separate approval is required for applying that exact plan. Shared artifacts are a separate decision; production is not touched. No Kubernetes application manifests are applied. **Rollback:** reviewed nonprod destroy plan only after dependent resources are removed; preserve state, bootstrap, evidence and approved artifacts. **Cost:** control plane, nodes, one NAT, CloudWatch/Flow Logs, KMS, data transfer.

## Stage C — OIDC identity canary (approval required)

Protected GitHub `qa` workflow obtains only `id-token: write`, assumes the exact role, and calls `aws sts get-caller-identity`; no write API. Verify repo/ref/environment/audience/account/role and that QA cannot assume prod. **Rollback:** disable workflow/trust after preserving audit evidence. **Cost:** negligible STS/log usage.

Before this canary, create the GitHub `qa` Environment manually with protected `main` branch policy and required reviewers where supported. After Stage B outputs exist, set only non-secret variables: `AWS_REGION`, `AWS_QA_DEPLOY_ROLE_ARN`, `ECR_REPOSITORY_URL`, `EKS_CLUSTER_NAME`, and `CODEBUILD_RUNNER_PROJECT`. The trusted publisher workflow uses repository variables `AWS_REGION`, `ARTIFACT_PUBLISHER_ROLE_ARN`, `ECR_REPOSITORY_URL`, `AWS_ACCOUNT_ID`, and explicit `ENABLE_ECR_PUBLICATION`; no AWS authentication secret is needed. Do not configure production Environment in M7 and do not invent output values.

## Stage D — CodeBuild runner canary (approval required)

First complete repository-scoped CodeConnections GitHub App authorization outside Terraform until `AVAILABLE`. Then configure only QA runner and trigger one harmless protected job to report tool versions and prove private API reachability with read-only checks. Verify ephemeral cleanup, target VPC/subnet/SG/logs, and no deploy authority on CodeBuild service role. No PAT. **Rollback:** disable webhook/project and revoke connection. **Cost:** one CodeBuild run, ENI/NAT and logs.

## Stage E — clean candidate build and assurance

After the M7 source is reviewed/committed, start from a clean main SHA and verify `HEAD`, worktree cleanliness, and unchanged Dockerfile/dependency inputs against the approved M6 source. Build exactly once; preserve the candidate through runtime validation, SBOM, Trivy, provenance, canonical findings, release evaluation and eligibility. Require matching digests/checksums, release `pass`, clean worktree and publication `eligible`; `conditional_pass` stays blocked. A verify-only workflow run cannot supply a later publish run because that would build a new candidate. The publish-mode run must carry the one build directly into the publish step. **Rollback:** discard candidate and rerun only from approved clean committed source. **Cost:** local/CI compute and scanner DB downloads, no AWS resources.

## Stage F — ECR publication (approval required)

Only after A, C and E's prerequisites pass and the ECR stack exists through separate authorization: run the trusted main workflow with `publication_mode=publish`, exact publisher OIDC role, explicit enablement, approved region and Terraform ECR URL. Within this single run the workflow builds once, completes all assurance, verifies `eligible`, assumes publisher OIDC and pushes that already-assured Git-SHA locator. Resolve ECR digest, require exact match, then write the published manifest. Never run verify mode followed by publish mode as a two-run promotion; never publish `latest` or rebuild between assurance and publication. **Rollback:** immutable images cannot be overwritten; revoke publisher trust and quarantine/remove only through reviewed retention process. **Cost:** storage/scanning/transfer.

## Stage G — post-publication verification (approval required)

Read ECR metadata for exact repository/tag/digest; verify immutability, digest equality, scan status and manifest checksums. No deployment occurs in M7. **Rollback:** mark evidence unusable, revoke trust if compromised, retain artifact for investigation. **Cost:** API, scan and storage.

## Stop boundary

M7 ends before Stage A. Do not run Terraform apply/destroy, AWS create/update/delete/put/attach/authorize, image push, live federation, CodeBuild, or Kubernetes deployment without the relevant explicit human approval. Roadmap: M7 is nonprod AWS activation and clean artifact publication; M8 is QA Kubernetes deployment/runtime assurance.

## Nonprod teardown plan (documented only; not executed)

Teardown requires its own approval, a fresh saved destroy plan, a second-person review, and confirmation that no QA test or evidence capture is active. Never destroy production or the state bootstrap in this procedure.

1. Freeze platform changes, preserve the current state object/version, record ECR digests and required evidence/retention, and identify orphan resources from the account inventory.
2. If a later milestone deployed workloads, stop traffic and remove QA Kustomize resources first. Delete Ingress/controller-owned ALBs and wait for AWS load balancers, target groups, and ENIs to disappear before cluster teardown. M7 has no application workloads or ALB.
3. Disable the QA CodeBuild webhook/project trigger, wait for builds to finish, then remove the runner project and runner security group/ENIs. Preserve runner logs for the approved retention period. M7 leaves this project absent until the GitHub connection is authorized.
4. Remove the EKS managed node group and verify EC2 instances/volumes terminate; then remove cluster add-ons, access entries/policies, and EKS control plane in Terraform dependency order. Preserve any required control-plane logs.
5. After EKS and CodeBuild no longer use the VPC, remove VPC endpoints, NAT gateway/EIP, route associations/tables, subnets, internet gateway, flow-log attachment, and VPC. Allow Flow Log delivery to settle before handling its log group.
6. Retain or archive required CloudWatch groups/evidence and do not delete KMS keys as part of routine teardown. Key deletion has a waiting window and can destroy access to retained logs or state.
7. Keep the separate shared ECR artifact stack and approved release/rollback digests. It can be removed only by a distinct reviewed decision after confirming no environment or recovery process uses it.
8. Keep the bootstrap S3 bucket, all state versions, lockfile history, and state KMS key. A nonprod destroy plan must never contain bootstrap, artifacts, or production addresses.

Before any future destroy, inspect the full JSON plan and require zero changes outside the intended nonprod workspace, no bootstrap/artifact/production resources, and no retained-evidence/key/state deletion. This runbook ordering is validated offline by infrastructure tests; no destroy plan was generated and no destroy was run.
