# GitHub Environments contract

Milestone 5 defines the repository settings contract. Terraform does not configure GitHub repository Environment rules, reviewers, or branch protections, and no AWS credentials are stored as GitHub secrets.

| Environment | Use | Allowed deployment ref | Approval | Environment variables |
| --- | --- | --- | --- | --- |
| `qa` | QA deployment to `graa-nonprod` namespace `qa` | `main` only; configure in GitHub Environment deployment branch rules | No required human reviewer by default; retain protected-branch checks | `AWS_REGION`, `EKS_CLUSTER_NAME`, `DEPLOY_ROLE_ARN`, `CODEBUILD_RUNNER_PROJECT` |
| `production` | Production promotion/deployment to `graa-prod` namespace `production` | `main` only; configure in GitHub Environment deployment branch rules | Required reviewer(s), prevent self-review, and disable administrative bypass where repository settings permit | `AWS_REGION`, `EKS_CLUSTER_NAME`, `DEPLOY_ROLE_ARN`, `CODEBUILD_RUNNER_PROJECT` |

Values are non-secret identifiers exposed by Terraform outputs. Use GitHub Environment variables, not secret fields, for role/project/cluster names and region. The relevant AWS account numbers are already in the role ARNs and are not credentials. Jobs request only `contents: read` and `id-token: write`; permissions should be set per job. Deployment workflows bind their protected job to the corresponding `environment` before requesting its OIDC token.

The AWS trust `sub` values are exact:

- QA: `repo:Ibraheemolasupogit/devsecops-application-security-pipeline:environment:qa`
- production: `repo:Ibraheemolasupogit/devsecops-application-security-pipeline:environment:production`
- artifact publication: `repo:Ibraheemolasupogit/devsecops-application-security-pipeline:ref:refs/heads/main`

The required `aud` is `sts.amazonaws.com`. Environment subjects do not contain a branch; the GitHub Environment's selected deployment branches and required reviewers provide those controls. Do not widen the AWS `sub` to `repo:<owner>/*`, use an environment secret for AWS keys, or let a production job request the QA role.

The CodeBuild project label is an execution-routing contract, not an authentication mechanism. The QA and production project names are distinct Terraform outputs. Jobs use `runs-on: codebuild-${{ vars.CODEBUILD_RUNNER_PROJECT }}-${{ github.run_id }}-${{ github.run_attempt }}`, matching AWS's documented CodeBuild-hosted runner label. AWS can start an ephemeral runner for queued jobs before an environment approval if its GitHub connection cannot read the deployment/environment state; the bootstrap must grant the documented connection permissions and M6 must prove approval ordering before using the runner for a protected job. Do not treat a GitHub Environment name alone as approval enforcement.

The CodeConnections GitHub App connection is AWS-side source/webhook authorization managed through CodeConnections. It is not an Environment secret, an OIDC credential, or a static AWS key. See [CI identity and private EKS access](../architecture/ci-aws-identity-and-private-eks-access.md) and [runner bootstrap](codebuild-github-runner.md).
