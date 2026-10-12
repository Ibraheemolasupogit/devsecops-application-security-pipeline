# ECR publication contract

The M3 artifacts stack exports the ECR repository URL and M5 exports `artifact_publisher_role_arn`. Repository variables consumed by `.github/workflows/build-publish.yml` are:

| Variable | Use |
| --- | --- |
| `ENABLE_ECR_PUBLICATION` | Explicit operational switch; must be `true` for the manually requested publish mode |
| `ARTIFACT_PUBLISHER_ROLE_ARN` | Exact M5 publisher role output, trusted for this repository's `main` ref |
| `AWS_REGION` | Region containing that ECR repository |
| `ECR_REPOSITORY_URL` | Exact M3 `genomic-research-access-api` repository URL |
| `AWS_ACCOUNT_ID` | Expected account passed to the pinned AWS credentials action's account guard |

No GitHub secret contains AWS credentials. The workflow requests an OIDC token and assumes the existing publisher role. It uses the AWS CLI to obtain ECR authorization, tags the already-built local image with `git-<full SHA>`, pushes that tag, queries ECR for the resulting image digest, and compares it with the Buildx candidate digest. The image digest, not the tag, is stored in the release artifact. ECR immutable-tag enforcement makes a duplicate tag fail instead of silently replacing a previous image.

Normal pull request and main-branch push runs only verify; they cannot enter the publish steps. Manual publication must be started from `main`, request mode `publish`, have the explicit enablement variable and all M3/M5 outputs, and produce an unconditional `eligible` decision. A conditional release decision remains blocked pending the approval semantics already required by release assurance. No real publication is part of Milestone 6 validation.

`scripts/container_supply_chain.py publish` is fail-closed: it requires the explicit live-publication switch, the publisher role contract, AWS region/repository agreement, GitHub Actions OIDC workflow context, an eligible decision, matching local image ID, successful ECR push and exact registry digest match. ECR image scanning is still an AWS-side later assurance input; M6's release gate is the local Trivy scan of the exact built candidate.
