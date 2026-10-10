# Current-State Audit — EKS Evolution Milestone 1

Audit date: 2026-10-10. Scope: existing completed Product Security reference; architecture only. No AWS resource existence or production readiness is inferred from local evidence.

## Repository baseline

Branch `main`, HEAD `8928245` (Fix final Bandit AppSec findings); one worktree at the repository root, initially clean (`git status --short` empty). Latest preceding commits: `671e16e` container connectivity/evidence replay; `291b722` Gitleaks fixture/server lifecycle; `dcd4447` Schemathesis diagnostics; `c1f48a4` authenticated Schemathesis state. 852 tracked files. No applicable AGENTS.md found. Existing numbered decisions are 1–6 in `docs/portfolio/architecture-decisions.md`; no dedicated ADR directory exists. Decision 7 continues that sequence.

Inspection covered README, docs and threat registers, all 16 workflows, Makefile, pyproject, Dockerfile, application routes/services/repositories/security packages, scripts, scanner configuration and fixtures, governance configuration, Terraform modules and both compositions, outputs/security, reports/security, and schemas/security. Historical documentation sometimes describes earlier milestone boundaries: actual Terraform now includes WAF rules, despite older deployment-boundary prose saying otherwise.

## Area dispositions

| Area | Classification | Evidence and rationale |
| --- | --- | --- |
| Application | retain_and_extend | FastAPI routes, Pydantic schemas, service boundaries and synthetic catalogue are small and testable. Extend readiness/configuration for deployment; do not replace domain behaviour. |
| Authentication | refactor | RS256 validator checks algorithm, issuer, audience, lifetime and roles. Local issuance and fixture keys are demonstrations; add trusted IdP/JWKS rotation and fail-closed production configuration. |
| Authorisation | retain_and_extend | Deny-by-default permission matrix and per-object service checks prevent cross-user access/self-approval. Preserve regression tests through persistence migration. |
| Data persistence | replace | Repositories use dictionaries/lists; main.py seeds every process. Replace production adapters with durable DynamoDB; retain in-memory adapters for local tests. |
| Docker/container | retain_and_extend | Multi-stage wheels, non-root runtime, removed packaging tools and healthcheck. Pin base digest, align numeric UID with ECS reference user 10001, add Kubernetes probes and test read-only runtime. Apt upgrades make rebuilds time-dependent. |
| Terraform | refactor | Nine modules: networking, compute, IAM, ECR, KMS, secrets, datastore, observability, audit. Retain controls, separate ECS reference from future EKS composition/state; no EKS Terraform in M1. |
| AWS architecture | retain_and_extend | Private workloads, endpoints, managed data, encryption and management audit remain useful. Add EKS control-plane/network/controller identity boundaries. |
| CI/CD | refactor | 13 independently triggered workflows plus 3 reusable definitions; no deployment DAG or artifact handoff. Consolidate execution ownership and gates later. |
| AppSec | retain_and_extend | Gitleaks, Semgrep custom rules, Bandit, pip-audit, CycloneDX, Checkov, Trivy and native raw outputs remain. Checkov wrapper uses soft-fail: downstream policy enforcement must be explicit. |
| Dynamic security | retain_and_extend | Boundary pytest, Schemathesis and ZAP have bounded local targets. Preserve local checks; add separately authorised QA endpoint execution without relaxing localhost defaults globally. |
| Findings normalisation | retain_and_extend | Stable IDs, adapters, deduplication, source lineage, ownership, contextual risk and SLAs. Add digest/environment/run attribution and real runtime exposure. |
| Release assurance | retain_and_extend | Rules and approval records exist; current workflow evaluates rather than enforces. Require enforcement and validated actual approvals before deployment. Local conditional_pass is not a production permission. |
| Vulnerability lifecycle | retain_and_extend | State machine, verification-before-closure, expiry, false-positive evidence and exception roles remain. Persist real operational history; do not reinitialise away unresolved findings each run. |
| Evidence | retain_and_extend | Checksums, source manifests, replay and sensitive-content checks are strong. Fixed January timestamps/not_deployed describe fixtures; introduce versioned live deployment evidence without rewriting historical facts. |
| Developer enablement | retain_and_extend | Guidance catalogue, prerequisites, PR checklist and control mapping remain; add EKS/digest/rollback guides. |
| Security Champions | retain_and_extend | Programme policy, squad coverage, workshops, maturity and escalation remain; distinguish synthetic programme evidence from actual participation. |
| Integration contract | retain_and_extend | Versioned export/checksums/consumer validator remain contract-only. Extend compatibility deliberately for runtime metadata; no external writes. |
| Observability | refactor | Structured correlation logs, ECS container insights, flow logs, basic ALB alarms and CloudTrail exist as code. Add EKS/application telemetry and actionable alerts. |
| Deployment/runtime | replace | ECS task/service reference becomes historical alternative; target EKS workload/controller model. No current deployment exists to migrate or destroy. |

Retire later: duplicate generated copies, redundant workflow entrypoints after parity validation, mutable deployment tag references and any demonstration-only production defaults. Do not retire the security-engineering capabilities or remove ECS code in M1.

## Terraform detail and operational gaps

- **Network:** public ALB/private application subnets across configured AZs; default security group denies traffic; optional single NAT disabled in dev/prod. Interface endpoints: ECR API/DKR, Logs, Secrets Manager; S3/DynamoDB gateway endpoints; optional VPC Flow Logs. EKS adds IP-capacity, CNI/network-policy, API endpoint and EKS Auth/STS connectivity planning. Existing task egress is only HTTPS within VPC; endpoint design cannot be assumed complete for new workloads.
- **ECR:** immutable tags, KMS, scan-on-push, approved execution-role pulls, count-based retention of 30 images. Preserve deployed/rollback digests beyond that simple retention rule.
- **ECS/Fargate:** private tasks, no public IP, read-only root, dropped capabilities, execution/runtime role split, rollback circuit breaker. Dev one task, prod two; production input already requires sha256 digest. UID 10001 is declared in task but Docker creates an unpinned system user. ECS environment variables ENVIRONMENT/PORT do not set GRAA_ settings; image omits tests/fixture public key. Deployment needs explicit configuration/key provisioning.
- **ALB:** HTTP/HTTPS, production certificate precondition, TLS policy, WAF managed rules with authorization redaction, deletion protection, optional access logs currently unset. Replace ECS wiring with Ingress/controller ownership; avoid Terraform and controller managing the same ALB.
- **IAM/OIDC:** exact repository subject and STS audience in trust, existing provider assumed rather than created. Runtime table/index permissions scoped, but deployment policy contains service wildcards and Resource=* including IAM PassRole. Region restriction alone is insufficient; bootstrap must be separated from routine deploy.
- **KMS:** application/secrets/audit keys rotate with deletion windows; policies reference ECS identities and service principals. Reassess service-specific conditions, key bootstrap ordering and least privilege; do not mechanically reuse for EKS.
- **Secrets Manager:** metadata only; values outside Terraform; rotation deferred. JWT public key is configuration, not a private secret. No IdP integration.
- **DynamoDB:** PAY_PER_REQUEST pk/sk plus gsi1, KMS, PITR, prod deletion protection/preconditions. No boto3 dependency or runtime adapter; no actual access-pattern implementation.
- **CloudWatch:** encrypted ECS/flow groups, ALB 5xx and target-health alarms; compositions pass name prefixes rather than real ARN suffix outputs. Prod CloudTrail log retention passed as 2555 days requires supported-retention verification. Notifications default empty. These are reference gaps, not validated live monitoring.
- **CloudTrail:** multi-region management events, validated logs, encrypted/versioned/private S3, secure transport, lifecycle, SNS and CloudWatch. Targeted data events are deferred. S3 access logging targets the same bucket and needs review for recursive logging; service policies need operational validation.
- **State:** dev/prod backend examples, no provisioned backend. Separate encrypted state/locking/bootstrap and protected destroy plans remain future work. Root infrastructure is not itself the complete environment composition.

## Workflow inventory and current dependency reality

All 13 entrypoints run on PR/push to main except portfolio-readiness (manual and PR). All 3 reusable files use workflow_call; no existing caller references them. Jobs generally install dependencies separately, verify checked-in evidence and generate only their own domain. Independent workflow success does not prove evidence came from the same image/run. Source attestations and cross-workflow artifacts are absent. Current CI does not configure AWS credentials or publish to Docker Hub/ECR.

| Existing file | Current responsibility | Future owner |
| --- | --- | --- |
| ci.yml | Quality, API/threat/infrastructure verification, Docker build | pr-validation.yml; build moved to build-publish.yml |
| appsec.yml | Secret/SAST/SCA/SBOM, AppSec evidence | security-assurance.yml; image SBOM in build-publish.yml |
| container-security.yml | Separate image build/Trivy | build-publish.yml |
| terraform-security.yml | Terraform validation, policy tests, Checkov | pr-validation.yml + security-assurance.yml |
| api-security.yml | Local pytest/Schemathesis/ZAP/evidence | security-assurance.yml locally; runtime-assurance.yml in QA |
| findings.yml | Canonical normalisation/risk/ownership | security-assurance.yml; runtime-assurance.yml updates |
| release-assurance.yml | Evaluate/report release rules | security-assurance.yml plus enforced QA/prod gates |
| vulnerability-management.yml | Lifecycle/exception validation and reports | security-assurance.yml + scheduled runtime-assurance.yml |
| security-evidence.yml | Consolidation/source integrity/reports | security-assurance.yml and runtime-assurance.yml |
| developer-enablement.yml | Prerequisites/guidance/tests | pr-validation.yml; security-assurance.yml evidence |
| security-champions.yml | Programme config/metrics/evidence | security-assurance.yml governance jobs |
| integration-contract.yml | Versioned export/lineage/consumer validation | security-assurance.yml and runtime-assurance.yml |
| portfolio-readiness.yml | Quality/portfolio readiness | security-assurance.yml manual portfolio job |
| reusable-quality.yml | Standalone reusable quality definition | Called by pr-validation.yml after parity review |
| reusable-appsec.yml | Fast scans and AppSec evidence | Extend/call from security-assurance.yml; current fast scans are not full assurance |
| reusable-security-evidence.yml | Consolidated evidence | Extend/call from assurance owners with explicit inputs |

Future count: six entrypoints plus three reusable definitions (nine files), subject to M2 parity checks. Preserve branch protections during check-name migration.

## Generated clutter

Tracked `.coverage 2`, `.coverage 3`, `.coverage 4`; five `outputs/portfolio/* 2.*` copies; `outputs/security/appsec/raw/gitleaks 2.json`. `.gitignore` only excludes exact `.coverage`, not suffixed files. Validation regenerates metadata and portfolio generation deletes duplicate copies. Restore these side effects in M1; classify/remove with reviewed provenance and ignore rules in M2. Do not broadly clean outputs or historical scanner evidence.

## Baseline validation

Executed before authored changes. Logs retained locally at `/tmp/eks-m1-validation/`; this temporary path is not a portable repository artifact. Python 3.12.8 on Darwin ARM64, Terraform 1.15.8, Docker CLI 28.3.3. CI specifies Python 3.11/Terraform 1.8.5; local success is not CI-version parity.

| Command | Exact result | Interpretation |
| --- | --- | --- |
| make quality | exit 0; 254 passed, 5 warnings; 85.82% coverage; auth 7 passed/12 deselected; API 19 passed; infrastructure 10 passed | Ruff/mypy/threat and checked-in evidence verifiers passed; Terraform fmt ran, init/validate are not part of this target |
| make appsec-full | exit 2 at dependency-audit; pip temporary environment upgrade failed in sandbox | Earlier Gitleaks, Semgrep (0 findings), Bandit ran; later stages not reached |
| make appsec-full (approved unrestricted retry) | exit 2; pip-audit reported 14 vulnerabilities in PyJWT 2.13.0; scanner exit 1 | Genuine live dependency finding; 13 advisories have listed fixes, one none. SBOM/Checkov/build/Trivy not reached. No suppression or dependency change in M1 |
| make dynamic-full | exit 2; pytest 8 passed/2 warnings; Docker socket permission denied | Schemathesis pull blocked; full assurance incomplete |
| make dynamic-full (approved unrestricted retry) | exit 2; pytest 8 passed/2 warnings; Cannot connect to Docker daemon | Daemon stopped; Schemathesis/ZAP did not execute; do not substitute fixtures as live results |
| make evidence-full | exit 0; 9 source domains verified | Existing reference evidence, not completed fresh scanner run |
| make integration-full | exit 0; export/compatibility/integrity verified | Local contract only |
| make portfolio-full | exit 0; generation/reports/verification passed | ready_with_limitations is not deployment readiness |
| make final-validation | exit 0; 254 passed; 85.82% coverage; downstream evidence/integration/portfolio passed | Does not run full AppSec or dynamic scanners |
| git diff --check | exit 0 | No whitespace errors |
| git status --short | exit 0; generated outputs/reports changed, five duplicate portfolio files deleted | Initially clean; validation side effects restored before delivery |

Warnings include synthetic HMAC key-length negative tests and Starlette 422 deprecation. Do not remove negative tests or weaken coverage/security policies to force green. See the post-change validation record appended below.

## Post-change validation and final scope

| Command | Result |
| --- | --- |
| make format | exit 0; 190 Python files unchanged; Ruff fixes made no code changes |
| make format-check | exit 0; 190 files formatted |
| make lint | exit 0 |
| make type-check | exit 0; no issues in 173 source files |
| make test | exit 0; 254 passed, 5 warnings |
| make quality | exit 0; 254 passed, 5 warnings; 85.82% coverage; auth/API/infrastructure checks passed |
| make final-validation | exit 0; quality and evidence/integration/portfolio completed |
| git diff --check | exit 0, including after generated-output restoration |
| git status --short | exit 0; final scope: modified README.md and five new architecture documents |

Post-change validation regenerated tracked evidence and deleted the same five duplicate portfolio copies; those side effects were restored to HEAD from the initially clean worktree. No original generated files were deliberately cleaned. The final documentation-only state retains the original historical evidence. Local link checks passed for all five new documents. Required scanner failures above remain unresolved; successful final-validation verifies existing evidence and does not establish fresh full scanner coverage. Policies, dependencies, Terraform, workflow files and runtime code remain unchanged. No AWS resources were created, no deployment occurred, and no commit or push occurred.
