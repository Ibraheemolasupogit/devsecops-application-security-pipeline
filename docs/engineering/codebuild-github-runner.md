# CodeBuild-hosted GitHub Actions runner foundation

Each future deployment job runs on a fresh AWS CodeBuild-hosted GitHub Actions runner inside the VPC belonging to its destination cluster. There is one logical project per environment: QA in nonprod and production in prod. CodeBuild runner instances are ephemeral per GitHub Actions job; no persistent EC2 runner fleet is defined.

## One-time connection bootstrap

The CodeBuild runner feature needs a GitHub source connection and a `WORKFLOW_JOB_QUEUED` webhook. Terraform deliberately does not create/authorize the connection: a connection may require an external GitHub App installation and user authorization, and an AWS connection can remain pending until completed. Bootstrap an AWS CodeConnections GitHub App connection scoped to this repository, complete authorization, wait for `AVAILABLE`, and pass its ARN to the environment's untracked Terraform input. Do not use a personal PAT. Do not commit an App private key, OAuth client secret, webhook secret, or connection secret. AWS manages the connection's credential material.

AWS's CodeBuild runner documentation lists GitHub App/OAuth/PAT approaches and states that the GitHub App runner integration needs repository Administration read/write permissions for runner registration. Use a dedicated GitHub App installation limited to this one repository and review its permission set with the repository owner. Do not grant organization-wide access. If this permission is unacceptable, stop before enabling the runner and reassess the execution product; do not silently substitute a personal PAT.

Terraform creates the project, workflow-job webhook filter, project log group, VPC ENI service role, and private SG once given an available connection ARN. It does not create GitHub settings, app credentials, webhook secrets, or runner registrations manually. The configured project source is this exact repository; filters match only `deploy-qa` or `promote-production` workflow names. Future jobs must use `runs-on: codebuild-<project-name>-${{ github.run_id }}-${{ github.run_attempt }}` with the exact per-environment project output. That label routes one job to a fresh runner and is not an IAM credential. Environment protection and branch restrictions remain separately governed GitHub settings.

## Role separation and OIDC behavior

The CodeBuild service role allows project log writes, VPC ENI lifecycle, and use of the connection. It cannot describe EKS, publish to ECR, pass IAM roles, or assume the GitHub OIDC roles. Runner logs use the platform KMS key and 365-day retention. AWS documents that CodeBuild-hosted runners receive CodeBuild container credentials by default. Therefore service-role permissions are kept non-deploying even though those ambient credentials are present.

Inside a runner, the future workflow has `id-token: write` and uses GitHub's OIDC token to call STS `AssumeRoleWithWebIdentity` for its intended QA or production role. Do not use the ambient CodeBuild service role as a fallback or chain it into deployment authority. AWS's public documentation confirms the ephemeral GitHub runner and the service-container credential behavior, but this repository has not performed a live token test. M6 must run a non-mutating protected identity canary to verify the token subject/audience, role assumption, and that Environment approval is complete before CodeBuild starts. If any step fails, keep deployment disabled; do not insert static keys.

The short-lived OIDC role then calls only `eks:DescribeCluster`; the EKS access entry and Kubernetes RBAC perform API authorization. Network connectivity comes from the VPC runner path, not the OIDC token.

## Network and cost

The runner ENI attaches to all configured private subnets in the target VPC. No inbound SG rules are present. Egress is TCP 443 for GitHub, AWS control-plane services, and workflow tool downloads, plus TCP/UDP 53 to the VPC resolver. Internet destinations have dynamic address ranges, so 443 traverses the existing M3 NAT route. No additional VPC endpoints are justified for M5; S3 gateway endpoints already exist. Interface endpoints for STS, ECR API/DKR, Logs, CodeConnections, or other services would add hourly/data processing charges and require a later egress inventory. Keep nonprod on one NAT and production on per-AZ NAT as already decided.

The runner SG ID is authorized for TCP 443 to the private EKS cluster SG. There is no public cluster endpoint. The one-job project concurrency cap limits burst/cost; set a future workflow-level concurrency key to avoid simultaneous promotion races.

## Future GitHub contract

Illustrative only; this file does not add a runnable deployment workflow:

```yaml
permissions:
  contents: read
  id-token: write
environment: qa # production for the protected production job
runs-on: codebuild-${{ vars.CODEBUILD_RUNNER_PROJECT }}-${{ github.run_id }}-${{ github.run_attempt }}
```

The workflow must use the exact `DEPLOY_ROLE_ARN` from the matching Environment and fail if OIDC cannot be acquired. It must never set `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY`. Project name labels select a runner; IAM trust and Kubernetes RBAC authorize it.

See [AWS runner tutorial](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner.html), [connection access requirements](https://docs.aws.amazon.com/codebuild/latest/userguide/access-tokens-github.html), [CodeBuild ephemeral runner behavior](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner-questions.html), and [GitHub Environment contract](github-environments.md).
