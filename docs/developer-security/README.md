# Developer Security

This directory is the developer entry point for the local security workflow in this repository. It turns the controls from Milestones 1-10 into repeatable engineering steps for planning, implementation, pull requests, scanner triage, release assurance and evidence verification.

Use this index when you are unsure which check to run. The short path for most changes is `make quality`, `make appsec-fast`, `make findings-full`, `make release-full`, `make lifecycle-full` and `make evidence-full`. Use `make security-assurance-full` before a high-risk pull request or after changing authentication, authorisation, dependencies, Terraform, Docker, scanner policy or generated evidence.

## Guides

- [Secure development guide](secure-development-guide.md)
- [Getting started securely](getting-started-securely.md)
- [Local security workflow](local-security-workflow.md)
- [Pull request checklist](pull-request-security-checklist.md)
- [Authentication](authentication-guide.md)
- [Authorisation](authorisation-guide.md)
- [Object-level authorisation](object-level-authorisation-guide.md)
- [Secure API checklist](secure-api-checklist.md)
- [Input validation](input-validation-guide.md)
- [Logging and audit](logging-and-audit-guide.md)
- [Secrets management](secrets-management-guide.md)
- [Dependency management](dependency-management-guide.md)
- [SBOM](sbom-guide.md)
- [Terraform security](terraform-security-guide.md)
- [Container security](container-security-guide.md)
- [CI/CD security](ci-cd-security-guide.md)
- [Dynamic testing](dynamic-testing-guide.md)
- [Vulnerability triage](vulnerability-triage-guide.md)
- [Remediation verification](remediation-verification-guide.md)
- [Security exceptions](security-exception-guide.md)
- [Release gates](release-gate-guide.md)
- [Secure code review](secure-code-review-guide.md)
- [Troubleshooting](troubleshooting-security-tools.md)
- [Glossary](glossary.md)
- [Onboarding checklist](onboarding-checklist.md)

## Command Matrix

| Category | Command | Purpose | Evidence impact |
| --- | --- | --- | --- |
| Setup | `make setup` | Create the local virtual environment. | No tracked evidence. |
| Quality | `make quality` | Run format, lint, type, coverage and core verifiers. | Verifies existing evidence. |
| API security | `make api-security-test` | Run authentication and authorisation tests. | No tracked evidence. |
| AppSec | `make appsec-fast` | Run secrets, SAST and dependency checks. | Refreshes scanner outputs. |
| AppSec | `make appsec-full` | Run the full scanner and evidence aggregate. | Refreshes AppSec evidence. |
| Dynamic | `make dynamic-full` | Run local-only Schemathesis, ZAP and boundary checks. | Refreshes dynamic evidence. |
| Findings | `make findings-full` | Normalise and enrich scanner findings. | Refreshes findings evidence. |
| Release | `make release-full` | Evaluate local release-gate evidence. | Refreshes release evidence. |
| Lifecycle | `make lifecycle-full` | Evaluate vulnerability lifecycle and exceptions. | Refreshes lifecycle evidence. |
| Evidence | `make evidence-full` | Build consolidated evidence across domains. | Refreshes consolidated evidence. |
| Enablement | `make developer-enablement-full` | Validate guides and generate enablement evidence. | Refreshes developer enablement evidence. |
| Cleanup | `make clean` | Remove local caches and build artifacts. | No tracked evidence. |

Success means commands exit with code 0 and the relevant manifest verifies. Failures should be fixed in the code, configuration, scanner policy or evidence generator. Do not bypass scanners or broaden suppressions to make a pull request pass.
