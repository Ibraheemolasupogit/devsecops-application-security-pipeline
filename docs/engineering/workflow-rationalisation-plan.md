# Workflow Rationalisation Plan

M2 inventory, with the M6 implementation update below. Target: six delivery entrypoints plus called reusable components, as defined in [M1 target architecture](../architecture/target-devsecops-platform.md). No workflow performs application deployment. The former standalone container workflow has been retired because it rebuilt independently of the digest-producing pipeline.

## Complete current-to-target mapping

All current workflows are retained during migration until required-check parity is demonstrated. Classification below records the eventual action, not permission to delete now.

| Current workflow | Classification | Target lifecycle owner | Preserved responsibilities |
| --- | --- | --- | --- |
| ci.yml | replace later | pr-validation | Quality/coverage/auth/API/threat/Terraform verification; container build removed and owned by build-publish |
| appsec.yml | merge later | security-assurance; build-publish SBOM | Gitleaks/Semgrep rule tests/SAST/SCA, raw evidence and reports |
| container-security.yml | retired in M6 | build-publish | Its independent build/scan was replaced by the build-once job and evidence artifact in build-publish.yml |
| terraform-security.yml | retain temporarily | pr-validation; security-assurance | Independent IaC format/validate/policy/Checkov audit check until parity proven |
| api-security.yml | replace later | security-assurance locally; runtime-assurance QA | Auth/object negative tests, Schemathesis/ZAP bounded local execution, diagnostics |
| findings.yml | merge later | security-assurance; runtime-assurance | Source verification, normalise/dedup/risk/owner/SLA, manifest lineage |
| release-assurance.yml | replace later | security-assurance; deploy-qa; promote-production | Validate/evaluate/report; add enforce and actual approval binding later |
| vulnerability-management.yml | merge later | security-assurance; runtime-assurance | Exception expiry, state transitions, verification-before-closure and history |
| security-evidence.yml | merge later | security-assurance; runtime-assurance | Required-domain verification, consolidation/replay and portable reports |
| developer-enablement.yml | merge later | pr-validation; security-assurance | Guidance/prerequisite/control mapping tests and onboarding evidence |
| security-champions.yml | retain temporarily | security-assurance governance jobs | Independently visible programme policy/maturity/coverage/escalation evidence |
| integration-contract.yml | retain temporarily | security-assurance; runtime-assurance | Independently visible contract/schema/consumer validation, checksum bundle; no external writes |
| portfolio-readiness.yml | merge later | security-assurance manual portfolio job | readiness/report/index generation; not a production gate |
| reusable-quality.yml | reusable component | pr-validation | Call after quality-version and Terraform prerequisite parity review |
| reusable-appsec.yml | reusable component | security-assurance | Extend explicit artifact inputs/outputs; current fast scans are not full assurance |
| reusable-security-evidence.yml | reusable component | security-assurance; runtime-assurance | Ordered aggregation with explicit verified run inputs |
| build-publish.yml | retain as M6 entrypoint | build-publish | One candidate build, image SBOM/Trivy, canonical findings/release integration, offline-default ECR publication gate |

## Six target entrypoints and ordering

pr-validation → security-assurance → build-publish → deploy-qa → runtime-assurance QA → promote-production → runtime-assurance post-deploy/scheduled checks. PR quality/security can execute in parallel where inputs are independent; cloud candidate jobs require trusted merged SHA and those checks. No privilege escalation through PR artifacts. Build once, scan/SBOM then immutable ECR digest publication; canonical findings and policy must bind to that artifact before QA. QA results extend findings/evidence and are reevaluated before protected production approval of the same digest. Production verification and remediation feed lifecycle/evidence/export.

Within assurance: threat/API/IaC/source/dynamic raw outputs → domain summaries → findings normalise/dedup/enrich → release decision → lifecycle/exception verification → consolidated evidence → integration → portfolio. Current final-validation verifies checked-in AppSec/dynamic evidence; it does not run fresh full scanners. Do not turn that into a deployment gate by renaming it.

## Duplication and drift found

- 16 workflows repeat checkout/Python/setup/pip installation; extras differ. Integration, release and portfolio use Python 3.12 while most use 3.11; Terraform setup is 1.8.5 in CI/IaC but absent in reusable-quality.
- Before M6, ci.yml and container-security.yml independently built images. M6 removes the CI build and retires container-security.yml; build-publish.yml now owns a single image build through optional publication. appsec.yml, terraform-security.yml and reusable-appsec still regenerate AppSec summaries/manifests with different raw subsets; these remain separate audit checks until evidence ownership is rationalised.
- Source verifiers repeat across findings/lifecycle/evidence/integration; portfolio runs quality again. These checks are useful audit boundaries but repeated setup/generation does not establish same-run lineage.
- Reusable definitions have no local callers. Reference content can be reused only after parity; reusable-appsec currently runs fast scans, not full AppSec. Most actions are SHA pinned, but release-assurance still uses mutable checkout@v4/setup-python@v5; do not fix YAML during M2.
- release-assurance evaluates and reports without enforce. Local fixture conditional_pass and synthetic role approvals are not protected production approval.
- Concurrent standalone workflows do not exchange exact run/SHA/digest artifacts. Existing checks mainly verify committed fixture bundles. Native scanner errors, bounded diagnostics and integrity failures must stay visible independently of report generation.

## Auditability and safe migration criteria

Keep independently named jobs/checks for source/AppSec, IaC, QA dynamic, release enforcement, evidence integrity, integration consumer compatibility and Champions governance even when entrypoints merge. Independence means separate outcomes/artifacts/owners and reviewer visibility, not necessarily a separate YAML. Production approval must remain isolated in its protected Environment; publisher/bootstrap/QA/prod identities must remain separated. Manual portfolio readiness can remain optional, distinct from enforceable security assurance. M6 keeps build, scan and optional publish in a single job so the local artifact is not reconstructed between assurance and publication.

For each migrated job: inventory commands/inputs/outputs/current required check names; prove positive/negative fixture coverage; add explicit workflow_call dependency contracts and exact-run artifacts; compare raw/normalised/release/evidence parity; preserve failure artifacts; update branch protection only after replacement checks are available. Archive/retire old workflow only after parity and reviewer acceptance. Preserve ordered one-writer-per-domain semantics and environment concurrency. Do not adopt broad workflow_run chains that trust artifact filenames or latest successful runs. Signing/provenance, cloud roles and runtime policy implementations stay in their roadmap milestones.
