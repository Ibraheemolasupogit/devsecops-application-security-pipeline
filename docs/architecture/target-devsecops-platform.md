# Target DevSecOps Platform

Target architecture only, 2026-10-10. Current implementation remains non-deployed. See [audit](current-state-audit.md), [decisions](platform-evolution-decisions.md), [ECS → EKS ADR](0007-ecs-to-eks.md), and [roadmap](eks-migration-roadmap.md).

## Delivery lifecycle and gates

Developer change → Pull Request → quality/security assurance → build image once → SBOM/provenance → image scan → immutable ECR publication → canonical findings → release-policy evaluation → QA deployment → smoke/integration/Schemathesis/ZAP → QA evidence → protected production approval → promote exact same digest → production deployment → post-deployment verification → metrics/logs/traces → remediation/rollback.

PR validation retains formatting, lint, typing, coverage, API negative tests, threat-model validation and IaC security tests. Fork PRs receive no cloud deployment permissions. Local dynamic tests remain part of PR assurance. Release candidates come from an approved merged SHA; optional PR image checks are disposable and never promoted as a different build of that candidate.

Build the candidate once, produce an image-derived CycloneDX SBOM and build metadata/provenance, scan that built artifact, then publish under an immutable Git SHA tag to ECR and capture the registry manifest digest. Initial provenance may be unsigned structured build evidence. Preserve scanner outputs and tool/database versions even on failure. Reconcile ECR scan-on-push results with the candidate's canonical findings; scan completion/failure must have explicit gating semantics.

Normalise source and image results, deduplicate, assign owners/SLAs and score actual deployment exposure. Evaluate and **enforce** QA release policy before deployment. Missing required evidence, scanner execution errors, expired exceptions or blocking findings stop the lifecycle; do not treat a report-generation exit code as a deployment gate. Publication itself does not authorise deployment.

QA deploys the digest using rendered Kustomize overlays. Smoke tests verify readiness, authentication and deployed digest. Integration tests verify durable data and object-level permissions. Schemathesis uses reviewed OpenAPI from the build (docs may be disabled at runtime) and short-lived synthetic test identities. ZAP is bounded to the QA allowlist/network; scan limits, seed reset and cleanup prevent destructive cross-environment traffic. Record ingress/TLS and runtime controls in QA evidence. QA findings feed the same canonical model, lifecycle and policy system; reevaluate policy after QA, before production approval.

The protected GitHub production Environment requires approved reviewers, permitted branches and no self-approval where supported. Reviewers see the exact SHA/digest, findings, valid exceptions, QA evidence hashes and policy decision. Approval is bound to that candidate; a changed digest/configuration invalidates it. Recheck evidence integrity, exception expiry, vulnerability freshness and production policy at promotion time. No fixed January fixture timestamps or synthetic approval roles authorise a live release.

Deploy the exact QA digest to production, verify rollout and application behaviour, confirm running image identity, then attach post-deployment evidence. Failures trigger a bounded rollback to a retained, previously approved digest/configuration; record failed rollout, rollback result and incident/remediation ownership. Data changes require compatible migration/recovery design; image rollback alone cannot reverse writes. GitHub per-environment concurrency serialises deploys/promotions; avoid cancelling a production rollout midway.

## Future GitHub Actions topology

Six entrypoints plus three actively called reusable definitions replace the current 16-file topology after parity review; no workflow edits in M1.

| Entrypoint | Trigger and responsibility | Required handoff |
| --- | --- | --- |
| pr-validation.yml | PR and main quality, API/threat/IaC structure, enablement checks | Required checks tied to SHA; call reusable-quality |
| security-assurance.yml | PR/main source/IaC/local dynamic assurance; governance, canonical findings, release/lifecycle, evidence/export; manual portfolio readiness | Fresh same-run scanner artifacts; call reusable-appsec and reusable-security-evidence |
| build-publish.yml | Trusted main candidate after quality/source assurance | Build once, SBOM/scan/ECR digest, canonical candidate bundle and enforced pre-QA decision |
| deploy-qa.yml | Explicit approved candidate in qa Environment | Verify release manifest; deploy digest; bounded smoke/integration; invoke runtime assurance |
| promote-production.yml | Candidate with successful QA evidence and protected production approval | Refresh/enforce policy; same digest; verify and record rollout/rollback |
| runtime-assurance.yml | QA deployment invocation, safe post-prod checks and scheduled re-scans/governance expiry | QA DAST findings/evidence, production verification, lifecycle updates and compatible exports |

Use explicit workflow_call outputs/dependencies or authenticated artifact download by exact run ID/SHA with checksum checks. Avoid independent workflow_run chains that infer trust from an artifact name or the latest successful run. Reusable helpers do not publish competing aggregate evidence; each owning run has one writer per domain and an ordered findings → release → lifecycle → evidence → integration chain. Required checks and environment gates must reference candidate evidence, not historical checked-in fixture verification. Preserve all current responsibilities using the audit mapping.

## Environment topology

| Model | Cost | Blast radius/isolation | Portfolio value | Complexity | Destroy/recreate | GitHub Environments |
| --- | --- | --- | --- | --- | --- | --- |
| A: shared non-prod cluster (QA + bounded test namespaces), separate prod cluster | Two control planes; shared non-prod capacity | Prod isolated from non-prod cluster failures; namespaces need RBAC/network/quota controls | Demonstrates realistic multi-environment platform without sprawl | Moderate; shared add-ons need ownership | Destroy non-prod independently; retain evidence/data; recreate from state/manifests | qa and production; optional preview environment with no prod trust |
| B: separate QA and prod clusters only | Same initial two-cluster baseline | Same prod boundary; fewer non-prod tenants | Strong parity, limited capacity reuse | Slightly simpler until extra testing clusters appear | QA independently disposable | qa and production |
| C: local Kubernetes development + on-demand QA EKS + separate on-demand prod demonstration | Lowest idle cloud cost when clusters absent | Separate cloud boundaries when present; local tests do not prove AWS integration | Honest low-budget portfolio option | Recreate/restore automation becomes essential | Explicit approved create/destroy windows; not a continuously available production service | qa and production still separate and protected |

Recommend **A**, with QA initially the only application namespace in non-prod and ephemeral test namespaces only when needed. Initially this has B's physical shape; do not create a third dev cluster. Local development remains local. Prefer separate non-prod/prod AWS accounts and VPCs/state to add an IAM/billing boundary; if budget/account availability requires one account, document weaker isolation and still separate clusters/roles/tables/secrets. Production availability commitments prohibit casual destroy; C is a budget mode for synthetic demonstrations, not production hosting.

Use small measured managed node groups in non-prod, with quotas and bounded scan jobs. Production replicas should span AZs with disruption budgets and enough spare capacity to roll out; a one-node demo is not highly available. Removing all workers does not remove EKS control-plane charges. Namespace separation cannot isolate malicious cluster administrators/controllers. Cluster upgrades/add-ons must be tested in non-prod first.

## Two separate identity architectures

**CI:** GitHub Actions OIDC → AWS STS AssumeRoleWithWebIdentity → environment-specific IAM role. Request id-token:write only in jobs needing federation; contents:read by default. Trust exact audience sts.amazonaws.com and exact repository subject. QA subject: repo:OWNER/REPO:environment:qa; production subject: repo:OWNER/REPO:environment:production. Environment subjects replace branch subjects, so enforce allowed branches and reviewer controls in GitHub Environment settings. Never grant privileged cloud roles to arbitrary PR code.

Use separate image-publisher, QA deploy, production deploy and infrastructure bootstrap/plan/apply roles. Publisher can upload only the build repository; QA role cannot reach prod. Routine deploy roles cannot create IAM/KMS/VPC resources or read secret values. Separate EKS access entries and namespace-scoped RBAC bind AWS deploy identities to required objects; deployment does not require cluster-admin. Bootstrap has tightly reviewed IAM PassRole/resource scopes, permission boundaries and protected state access. Existing broad reference policy is not carried forward. Private EKS API access requires a controlled runner/network path; prefer ephemeral trusted runners in the VPC, without persistent credentials, after access design is reviewed. No static CI AWS access keys. [GitHub OIDC guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).

**Runtime:** EKS workload identity → AWS services. Prefer EKS Pod Identity for managed EC2 nodes: dedicated API service account/association/role limited to its environment DynamoDB table and required indexes; separate identities for ESO, ingress controller and telemetry collectors. Use a supported AWS SDK's default credential chain and Pod Identity Agent. Temporary credentials supplied by federation are expected; no static access keys in images, Pod environment declarations, Kubernetes Secrets or config. Restrict node instance-role privileges and IMDS access so workload fallback cannot grant broader permissions. IRSA is an alternative only for a documented controller/SDK compatibility requirement; it uses service-account OIDC → STS and is unrelated to GitHub federation. Validate all chosen add-ons before fixing identity plumbing. [AWS workload identity comparison](https://docs.aws.amazon.com/eks/latest/userguide/service-accounts.html).

## Supply chain and promotion contract

One build → immutable ECR artifact → Git SHA metadata → registry digest capture → SBOM → vulnerability evidence → optional provenance/attestation → QA validation → promotion of exact same digest.

Build/publish stores a release manifest: repository, Git SHA, workflow run/attempt, image URI/digest/platform, SBOM checksum, scan results/checksums/timestamps/tool versions, provenance reference, canonical evidence bundle, policy version and decision ID. The manifest identifies evidence, not just a tag. Build dependencies/base images should be pinned by digest and reproducible resolution reviewed; one-build promotion guarantees identity even when rebuilds are not reproducible.

Prefer one build repository with read-only QA/prod pull permissions, including cross-account repository policy if accounts are separate. If later policy mandates separate registries, copy the same OCI artifact and verify destination digest rather than rebuild; no such copy is needed by the default target. Capture the OCI index versus platform manifest distinction and test the selected node architecture; begin with a single validated platform to limit ambiguity. Re-scan the same digest when evidence freshness expires without rebuilding it.

No latest, qa or prod mutable tag controls rollout. Environment records reference digest and configuration hash. ECR count-based retention must protect active, approved and rollback digests. Unsigned checksums establish consistency, not authenticity against a malicious producer. Signing belongs in a later M6/M12 extension once issuer/trust-root verification, keyless or KMS approach, registry retention and admission failure behaviour are decided. No signing implementation in M1.

## Kubernetes workload and ingress model

Recommend Kustomize alone: one base for Deployment, ClusterIP Service, service account and security controls; narrow QA/prod overlays for configuration/resource/replica/identity/ingress differences. Render and compare allowable differences before deployment. Use startup/readiness/liveness probes, requests/limits, non-root numeric UID, read-only root, dropped capabilities, seccomp, no privilege escalation, restricted Pod security and namespace-scoped RBAC. Bound writable tmp volumes. Network policy must be enforced by the selected CNI, not merely present as YAML. Add graceful shutdown and rollout timeout.

AWS Load Balancer Controller owns ALB targets/listeners through reviewed Ingress; Terraform owns VPC, IAM, DNS/cert prerequisites. Avoid dual ALB ownership and arbitrary privileged annotations/shared IngressGroups. QA and prod use distinct hostnames/ALBs and ACM certificates, HTTPS redirect, scoped security groups and applicable WAF controls. Route 53 records point to the owned ALB; domain ownership/ACM validation remains an open prerequisite. Do not add ExternalDNS just to manage two records. Restrict non-prod ingress to approved users/testing paths as appropriate. Backend HTTP/TLS decision requires documented trust boundary; TLS termination alone is not end-to-end encryption.

## Secrets architecture

AWS Secrets Manager → EKS workload identity → External Secrets Operator → namespace-scoped Kubernetes Secret → workload.

ESO is justified for declarative refresh/status and reuse of Secrets Manager without adding secret-fetching application code. Prefer an environment-isolated ESO controller service account/Pod Identity role with exact secret ARNs and necessary KMS decrypt conditions; in shared non-prod, use namespace-scoped controllers/roles or explicitly reviewed tenant boundaries rather than giving a single universal controller access to everything. Namespace SecretStore and ExternalSecret select only approved keys. Restrict who can create/change stores and external references; namespace scope alone does not constrain IAM. Avoid cluster-wide stores and PushSecret for this API. ESO's Pod Identity support relies on controller default credentials; do not assume arbitrary tenant service-account token references use Pod Identity. [ESO AWS provider guidance](https://external-secrets.io/latest/provider/aws-secrets-manager/).

Secret values are provisioned outside Terraform and never enter Git, build logs, artifacts or state. Workload mounts only required secret files; public JWT verification keys/JWKS URLs normally belong in configuration, private issuer keys never belong in the API. RBAC restricts Secret reads, supported encryption-at-rest controls protect API storage, logs redact tokens, and volume/environment refresh needs an explicit reload or controlled restart policy. Readiness gates detect missing values/sync failures; alert on stale refresh and test rotation. Deleting clusters must not delete authoritative secrets unintentionally.

Trade-offs: ESO adds a privileged controller, CRDs and secret copies in Kubernetes. Direct AWS SDK retrieval reduces copies but couples application to refresh logic. Secrets Store CSI is a valid file-mount alternative but adds another driver/rotation mechanism and does not best fit the chosen conventional Secret flow. Select ESO only; do not install both. If no actual private application values are needed, defer its installation until that need exists while retaining the architecture.

## Observability direction

| Option | Assessment |
| --- | --- |
| Prometheus | Strong Kubernetes metrics/PromQL; operating storage/HA adds cost; managed AMP still adds a backend |
| Grafana | Good cross-source dashboards; self-hosting/auth or managed workspace is unnecessary initially |
| Loki | Useful label-based logs; adds storage/retention/operations beside existing AWS logs |
| Tempo | Useful trace backend; another storage/availability responsibility |
| OpenTelemetry | Select instrumentation/collector standard; it is not a storage backend |
| AWS-native | Select CloudWatch metrics/logs/dashboards/alarms and X-Ray traces; reuse ALB/EKS/CloudTrail visibility |

Recommend one coherent initial stack: OpenTelemetry instrumentation/collector exporting metrics to CloudWatch, traces to X-Ray, structured stdout logs collected to CloudWatch Logs by one supported log agent. Use correlation/trace IDs across requests, DynamoDB calls and release records. Select exporters/versions in M11 and test telemetry loss/resource limits; do not deploy a parallel Prometheus/Grafana/Loki/Tempo stack. CloudTrail remains management audit, not application tracing. Cost, vendor coupling and query limitations are the trade-offs; adopt another backend only for a demonstrated unmet requirement. [AWS ADOT documentation](https://aws-otel.github.io/docs/introduction).

Dashboards must answer: Is the service available and within latency/error objectives? Which SHA/digest/config is deployed? Did this rollout change p95 latency/5xx? Are pods pending/restarting/OOM or capacity saturated? Is DynamoDB throttled/slow and are entitlement decisions consistent? Are authentication failures/denials/rate limits abnormal without exposing user tokens? Are secrets sync, certificate renewal and telemetry healthy? Which findings are overdue, exceptions expiring, releases blocked or rollbacks failing? How much do environments/namespaces/log ingestion cost? Define alert owners/runbooks; telemetry dashboards do not replace canonical evidence or create real Security Champions attendance.

## Persistence and application readiness

Keep DynamoDB as the target for synthetic dataset metadata, requests, entitlement queries and audit indexes. The code performs lookup by ID, lists by requester/time, evaluates approved access by subject/dataset and transitions approval state. No joins, SQL migrations or MySQL requirement exists. Add repository interfaces and DynamoDB adapters, with access-pattern tests for pk/sk and gsi1 rather than simply copying the reference schema. Add pagination instead of whole-table scans.

Use conditional writes/version checks to prevent concurrent/repeated decisions and transactions for coupled state changes where appropriate. GSI eventual consistency must not grant stale/revoked access; design authoritative entitlement reads. Preserve self-approval restrictions. Durable append-only audit events with restricted writes and an outbox/export path to protected S3 should avoid losing audit events when request writes succeed. Define retention, PITR/restore and failure semantics; CloudTrail management logs do not cover application audit. Keep synthetic data only and no genomic payloads. No database runs inside EKS and no EBS app volume is required. PostgreSQL could be reassessed if relational/reporting needs emerge; do not introduce MySQL because of course examples.

Multi-replica deployment is unsafe with current process-local request/audit state. Durable adapters, idempotency/concurrency behaviour and production IdP configuration are prerequisites for production. Rate limiting is also process-local and disabled by default: evaluate WAF/edge controls plus an appropriate shared limit mechanism only if necessary; do not silently claim per-process limits protect the cluster.

## Preserve the security operating model

| Capability | Delivery integration |
| --- | --- |
| Threat modelling | PR trust-boundary review; add cluster/node/controller/artifact threats and trace to runtime tests |
| AppSec scanners | Source/IaC/image assurance; preserve raw outputs and execution failure states |
| Canonical findings | Common image, QA and runtime records linked to SHA/digest/environment |
| Risk scoring | Real exposure/privilege/data context, ownership and SLA before release policy |
| Release policy | Enforced pre-QA and post-QA/pre-prod gates; GitHub approval does not override a block |
| Vulnerability lifecycle | Durable ownership/triage/history and verified remediation after rollout |
| Exception governance | Scoped owner-approved time-limited exceptions, rechecked at promotion |
| Evidence integrity | Schema/checksum/source replay and sensitive-content validation; access-controlled retention and candidate linkage |
| Developer enablement | PR checklists, local checks, onboarding, deploy/rollback/remediation guidance |
| Security Champions | Design review, risk escalation, workshops and control feedback; retain governance evidence |
| Integration contract | Versioned compatible export with runtime lineage; downstream ingestion remains separately authorised |

Extend evidence schemas with live timestamps, environment/deployment status, image digest, run identity, configuration hash and approval provenance. Preserve controlled fixtures for replay tests. Store portable release evidence in encrypted/versioned S3 with least privilege and retention; evaluate Object Lock only when retention/recovery requirements justify its cost/irreversibility. CI artifacts are a short-lived transport, not the sole assurance archive. Contract consumers must validate supported versions and lineage before accepting new fields/statuses.

## Cost and lifecycle discipline

No precise monthly estimate is defensible without region, hours, support tier/version, node types/counts, AZs, traffic, storage and retention assumptions. Before M3 price A and C with those assumptions and a budget ceiling. EKS charges depend on cluster support lifecycle; upgrade ownership prevents accidental extended-support spend. [AWS EKS pricing](https://aws.amazon.com/eks/pricing/).

| Recurring driver | Planning and control |
| --- | --- |
| EKS control plane | Two active clusters are baseline; destroy idle synthetic environments to stop cluster charges |
| Worker nodes | Minimal measured non-prod capacity, reuse namespaces; production AZ/spare capacity; schedule scale-down without claiming HA |
| NAT Gateway | Hourly/traffic costs; assess private endpoints vs NAT, including endpoint per-AZ charges; no automatic NAT per AZ for a demo |
| ALB/WAF | ALB hours/LCUs, WAF rules/requests; separate prod, safely reuse non-prod routing when justified; remove controller-owned ALBs on destroy |
| EBS | Node root volumes, IOPS/snapshots; avoid unnecessary stateful observability/application volumes |
| Route 53/ACM | Hosted zones/queries/domain renewal and certificate requirements; validate pricing for chosen certificate type |
| CloudWatch/X-Ray | Log ingestion/retention, custom metrics/cardinality, dashboards/alarms and trace sampling |
| S3 | Evidence/audit/state retention, versions/requests; lifecycle reviewed, do not destroy state/history with cluster |
| ECR | Images/SBOM/attestations/scan features/storage/transfers; retain rollback digests and expire unused builds |
| Observability resources | Collector/log-agent CPU/memory plus backend ingestion; one stack and bounded cardinality |
| Other AWS services | Interface endpoints, KMS, Secrets Manager, DynamoDB/PITR, backups and cross-AZ traffic also cost money |

Reuse non-prod nodes, minimise unnecessary operators, prefer S3/DynamoDB gateway access where suitable. NAT avoidance requires proving private connectivity to ECR/S3/Logs/Secrets, STS or EKS Auth as needed and required external IdP endpoints; interface endpoints are not free. Do not solve egress cost by exposing workers publicly. Use explicit environment destroy/recreate runbooks, state locks and protection boundaries. Retain prod data, authoritative secrets, ECR rollback artifacts and evidence independently; verify load balancer/volume/endpoint cleanup to prevent orphan spend.
