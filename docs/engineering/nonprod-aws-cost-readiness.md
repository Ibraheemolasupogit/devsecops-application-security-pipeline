# Non-production AWS cost readiness

M7 defines the first cloud footprint but does not create it. A defensible monthly estimate requires an approved account and region, cluster uptime, exact node/AZ choices, traffic, log volume/retention, CodeBuild minutes, storage, and current pricing. No total is stated until those inputs are known and priced against current AWS rates.

Pricing models checked 2026-10-12: AWS bills EKS by cluster/version-support tier and worker infrastructure separately ([EKS pricing](https://aws.amazon.com/eks/pricing/)); NAT by provisioned gateway-hours plus processed bytes and data transfer ([VPC pricing](https://aws.amazon.com/vpc/pricing/)); CodeBuild by build duration/compute type plus any used services ([CodeBuild pricing](https://aws.amazon.com/codebuild/pricing/)); CloudWatch by selected logs/metrics/queries and regional usage ([CloudWatch pricing](https://aws.amazon.com/cloudwatch/pricing/)). These pages describe changing regional rates, credits, and service options; no sample rate is applied to this plan because the primary region and workload inputs are not approved.

| Driver | Expected exposure and control |
| --- | --- |
| EKS control plane | Billed while the nonprod cluster exists, even with no workers. Schedule a destroy window for synthetic work. |
| EC2 managed node group | Initial nonprod bounds are min/desired/max 1/1/2 with configurable general-purpose instances. Use one small compatible node initially; verify fit and AZ capacity. |
| NAT Gateway and processing | Nonprod uses one NAT for cost control, trading away AZ-level egress resilience. Hourly, per-GB, and cross-AZ transfer can matter. Keep nodes/runners private. |
| CodeBuild execution | Projects are absent until a GitHub connection ARN is approved. Once enabled, bound compute/time/concurrency and log retention. |
| CloudWatch, VPC Flow Logs and CloudTrail data events | Ingestion, storage, query and audited S3 object-event charges; platform groups use 14-day nonprod retention, runner logs only exist when enabled. `ALL` flow logging is an explicit audit/cost choice. |
| KMS | Customer-managed key-month and request charges. Platform/ECR/state keys have separate lifecycles. Key deletion can make retained data unrecoverable. |
| ECR | Storage and transfer scale with retained digests. Untagged images expire after 30 days; tagged releases/rollback candidates remain. |
| S3 state | Object versions/requests cost money. No version expiration is configured because it could remove recovery points; monitor and review retention deliberately. |
| Data transfer | NAT, cross-AZ flows, image layers and logs can dominate light usage. Measure during a canary. |

No new interface endpoints are proposed. M3 has S3/DynamoDB gateway endpoints; CodeBuild access to GitHub and general AWS APIs currently uses NAT. Interface endpoints for STS, ECR, Logs or CodeConnections have per-AZ hourly/data costs and should follow observed need. Do not remove NAT until all GitHub and AWS dependencies have tested private routes.

## Nonprod composition inventory (configuration review, not a plan)

The nonprod root composes the following categories. Exact planned resource counts are **unavailable** until approved variable/backend inputs, matching Terraform 1.16.5, AWS identity/region, and a real saved plan exist. Do not interpret this category inventory as a reviewed Terraform plan.

| Category | Configured nonprod contents | M7 status |
| --- | --- | --- |
| VPC/networking | VPC, public/private AZ subnets, routes, internet gateway, one NAT/EIP, S3/DynamoDB gateway endpoints, default-deny default SG, VPC Flow Log | Required by composition |
| EKS control plane | Private API, KMS secret encryption, five control-plane log types, access configuration, administrator and deployment access entries | Required by composition |
| Managed nodes | One general-purpose managed node group and encrypted gp3 launch template in private subnets | Required, 1/1/2 node capacity bounds |
| IAM/OIDC | Cluster, node, CNI and flow-log roles; exact GitHub OIDC provider if no ARN input; QA deploy role and access entry | OIDC provider creation conditional on account provider input |
| KMS | One nonprod platform key and alias for EKS secrets/log groups | Required |
| CloudWatch/logging | Control-plane and Flow Log groups, Flow Log role/policy | Required, configured 14-day retention |
| ECR | Shared immutable application repository/key in `terraform/artifacts` | Separate composition, not part of nonprod plan |
| CodeBuild runner | Project, webhook, runner SG, service role/policy and log group | Disabled while connection ARN is null; requires external CodeConnections authorization |
| Production-only | Separate cluster, prod VPC, per-AZ NAT and production deployer access | Excluded from M7; no production changes |

Keep one shared nonprod cluster, minimal measured node capacity, and the runner connection unset until an approved protected canary. Tag with `Environment`, `CostCenter`, `Owner`, `Project`, and `ManagedBy`; set budget alerts before activation. Destroy disposable nonprod platform resources after controlled test windows, while retaining the state bucket/key, shared ECR artifacts, and required logs/evidence. Stage B's reviewed plan must supply exact counts and current regional prices before approval.

See the [activation runbook](../runbooks/nonprod-platform-activation.md).
