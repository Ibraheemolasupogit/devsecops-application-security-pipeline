# EKS cost controls

M3 code defaults are controls, not a monthly quote or provisioned budget. Before any authorised plan/apply, record account/region, uptime hours, AZ count, Kubernetes support tier, node capacity, traffic, storage and retention with a budget ceiling using current AWS pricing. No AWS account or precise monthly costs are assumed.

| Recurring driver | Foundation control and later obligation |
| --- | --- |
| EKS control plane | Two clusters only. STANDARD version-support policy; upgrade before support expiry. Destroy idle nonprod to stop its cluster charge |
| EC2 workers | One managed group per cluster; t3.medium x86 default; 1 desired nonprod, 2 prod; max 2/3. Measure memory, controller overhead and burst CPU credit costs; no HA/capacity claim from node count alone |
| NAT and cross-AZ transfer | Nonprod one NAT deliberately accepts AZ dependency and cross-AZ costs. Production per-AZ avoids that dependency but costs more. NAT-free is not a supported flag; prove full ECR/S3/Logs/EKS Auth/STS/IdP connectivity first |
| VPC endpoints | S3/DynamoDB gateway endpoints by default. No paid interface endpoint fleet. Compare endpoint per-AZ hours/traffic against NAT and security requirements before adding |
| ALB/WAF | Not created in M3. Later controllers must remove owned resources before cluster destruction; one ingress path per environment is sufficient |
| EBS | Encrypted 20-GiB gp3 node roots deleted on termination. No app or observability persistent disks. Account for orphan volumes/snapshots after failures |
| CloudWatch | All EKS streams and flow logs retained 14 days nonprod/90 days prod, encrypted. These diagnostic logs are not long-term canonical evidence. Increase/export retention for real compliance; limit flow ingestion and app cardinality after measurement |
| KMS | One key per cluster shared with scoped logs, separate artifact key, state key outside foundation. Rotation enabled; KMS key/API charges persist after node shutdown |
| ECR | One artifact repository; immutable tagged candidates/rollback images retained. Untagged expiry after 30 days; scan-on-push. Track storage growth and protect active digests before adding tagged expiry |
| S3/state/evidence | Separate bootstrap; versioning/request/retention costs. Retain state and durable evidence when nonprod is destroyed |
| Route 53/TLS | Later hosted zone/query/domain costs; no domain/certificate created here |
| Observability | CloudWatch/X-Ray direction; no duplicate Prometheus/Grafana/Loki/Tempo fleet or OTel controllers in M3. Bound future agent memory and backend ingestion |
| Application services | DynamoDB, Secrets Manager, backup/PITR and CloudTrail ownership later; avoid accidentally deploying the ECS reference alongside EKS |

Required Project/Platform/Environment/ManagedBy/Owner/CostCenter tags allow allocation. CostCenter is an explicit deployment input. No AWS Budget resources are created; a real billing owner/alerts remain prerequisites.

## Destroy/recreate boundary

Nonprod is disposable synthetic capacity, not a durable datastore. Do not run destroy as part of local validation. For a separately authorised teardown: preserve state/evidence, record versions/outputs/configuration, stop deployments, remove controller-owned ALBs/ENIs/volumes after their finalisers complete, export necessary diagnostic logs, obtain the reviewed destroy plan, verify correct account/state and destroy only the nonprod root. Check orphan NAT/EIP/endpoints/node volumes and reconcile costs afterward. Recreate from the same reviewed configuration and backend, then rerun identity/connectivity/health tests. Namespaces later share nonprod capacity rather than add QA/test clusters.

Artifact repository is independent with prevent_destroy and force_delete=false; removing a cluster must not remove retained images. Its key must also be retained whenever artifacts remain; do not target-destroy the key. Production deletion protection is true and requires an explicitly reviewed configuration change before deletion. It does not protect every dependent resource or data store. Keep prod access/state separate, and never assume scaling desired nodes to zero stops the control-plane/NAT/log/key bill. Current min capacity is at least one; synthetic nonprod savings come from authorised root teardown, not unsafe in-place overrides.
