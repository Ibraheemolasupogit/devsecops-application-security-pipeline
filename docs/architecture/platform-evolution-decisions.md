# Platform Evolution Decisions

M1 target decisions, 2026-10-10. None of these recommendations provision resources. See [audit](current-state-audit.md), [decision 7](0007-ecs-to-eks.md), [target](target-devsecops-platform.md), and [roadmap](eks-migration-roadmap.md).

| Capability | Current approach | Target approach | Decision | Rationale | Migration impact | Risk |
| --- | --- | --- | --- | --- | --- | --- |
| ECS Fargate → EKS | Non-deployed ECS reference | EKS managed node groups | replace runtime; retain ECS reference | Kubernetes delivery/security is the programme objective | New compute, RBAC, CNI, controllers, upgrades | More operations and recurring control-plane cost |
| Docker Hub vs ECR | Docker Hub base/scanner pulls; no app publication; ECR Terraform already exists | Private immutable ECR app artifact; pinned external tool/base dependencies | retain_and_extend ECR | AWS access control and digest promotion; no invented Docker Hub app migration | Add publication and pull policies | Registry retention/availability; external pull limits |
| Static credentials vs OIDC | OIDC trust reference; neither static CI keys nor live AWS auth implemented | GitHub OIDC/STS environment roles | operationalise OIDC; prohibit static keys | Short-lived identities and separated trust | Provider/bootstrap/role policies/environment protection | Incorrect subject permits unintended jobs |
| QA/prod artifacts | Local image builds and separate dev/prod reference repositories | One build repository, environment deployment records; cross-account read if needed | refactor | Avoid rebuilding per environment | Artifact handoff and repository policy | Promotion of wrong candidate |
| Mutable tags | Local milestone/ci tags; prod Terraform already demands digest | SHA tag metadata; deploy only @sha256 | retain_and_extend digest policy | Exact byte identity QA→prod | Capture/verify manifest digest | Multiarch index/child confusion |
| Workflow fragmentation | 16 files, parallel domain entrypoints | Six entrypoints, three called reusable definitions | refactor | Explicit assurance dependency DAG | Required check migration, artifact contracts | Lost check coverage/stale inputs |
| Kubernetes packaging | None | Kustomize base + QA/prod overlays | select Kustomize only | Reviewable differences for one API | Render/schema/policy tests | Overlay drift if patches unrestricted |
| Secrets Manager | Metadata only, ECS injection model | ESO per-environment controller identity and scoped SecretStore | retain_and_extend | Declarative reconciliation and rotation visibility | CRDs/RBAC/value provisioning/refresh | Controller compromise and Kubernetes secret copies |
| Workload identity | ECS execution/runtime roles | EKS Pod Identity for API/ESO/controllers | replace ECS trust in target | Per-service-account temporary SDK credentials | Agent, supported SDK, associations and endpoints | Node identity fallback/unsupported controller |
| ALB/Ingress | Terraform ECS ALB/WAF wiring | AWS Load Balancer Controller + Ingress, ACM/WAF | refactor | Kubernetes ownership of targets/routes | Controller IAM and constrained annotations | Shared ingress privilege/duplicate ownership |
| DNS/TLS | Certificate inputs; no DNS or issuance | Route 53 environment records + ACM DNS validation | extend | Stable endpoints and HTTPS in both environments | Domain ownership/protected record changes | Certificate expiry/misrouting |
| Dynamic location | Localhost-only | Retain local PR checks; bounded QA jobs in controlled network | extend | Test deployed digest/ingress without production attack traffic | New scoped QA execution mode | Unsafe target selection/scan disruption |
| Observability | Logs + ECS/ALB reference alarms | OpenTelemetry + CloudWatch metrics/logs + X-Ray traces | refactor | AWS-integrated small footprint | Instrumentation/exporters/dashboards | Ingestion cost/cardinality/privacy |
| Evidence integration | Deterministic fixed-date not_deployed bundles | Preserve replay; versioned SHA/digest/run/env-linked live bundles | retain_and_extend | Security gates must apply to deployed candidate | Schemas/adapters/retention/approval lineage | Hashes alone cannot prevent malicious replacement |
| Persistence | In-memory; DynamoDB reference | DynamoDB adapters with conditional transitions/outbox | replace production adapter | Actual key-oriented access workflow, no relational requirement | Access patterns, pagination, concurrency tests | Lost audit writes/incorrect entitlement consistency |
| Authentication | Local JWT/static test public key | Trusted IdP/JWKS with verified role mapping | refactor | Fixture identities cannot become production trust | Provider selection/rotation/failure tests | Role escalation or stale keys |

## Kubernetes packaging comparison

| Option | QA/prod drift | Complexity/reuse | Reviewability/parameterisation | Portfolio clarity |
| --- | --- | --- | --- | --- |
| Plain manifests | Duplicated resources drift easily | Lowest initial complexity, weak reuse | Direct YAML; manual repetition | Simple but weak evolution story |
| Kustomize | Shared base, narrow explicit overlays | Moderate, built into kubectl; sufficient for one API | Rendered YAML diff; image digest/replicas/config patches | Clear environment differences |
| Helm | Values/schema can constrain drift | Templates/chart lifecycle add complexity; strong multi-consumer reuse | Template indirection; broad parameterisation | More machinery than this single app requires |

Recommend exactly **Kustomize** for application packaging. Allow only documented environment deltas (namespace, role/table/secret references, replicas/resources, endpoint/config); digest is the promoted input. Render both overlays, validate schemas/security policy and compare allowed deltas. Do not introduce a parallel Helm application model. Platform add-ons should use pinned, separately owned installation manifests/automation; dependency distribution is not a second app packaging strategy. [Kubernetes Kustomize documentation](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/kustomization/).

## Deferred choices

Before M3 confirm region/accounts, budget and supported Kubernetes/provider versions. Before live QA settle runner connectivity and IdP test identities. Before production settle RTO/RPO, approval owners, evidence retention and recovery policy. Signing/attestation is assessed in M6 and enforced only after a trust-root/admission design and tamper tests exist; M1 implements neither.
