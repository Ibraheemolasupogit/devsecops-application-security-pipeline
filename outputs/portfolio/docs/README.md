# DevSecOps Application Security Pipeline

Portfolio repository for a synthetic FastAPI product secured through a full local Product Security operating model: secure design, API controls, Terraform reference architecture, AppSec scanning, dynamic testing, finding normalisation, release assurance, vulnerability lifecycle governance, consolidated evidence, developer enablement, Security Champions, and a Repository 5 integration contract.

The application uses synthetic, non-identifiable demonstration data only. It is not a production genomics platform, is not affiliated with or endorsed by Genomics England, and does not deploy AWS resources.

## 1. Portfolio Positioning

This repository demonstrates how product-security practices can be implemented as reproducible engineering workflows rather than slideware. The core product is intentionally small so the security system around it is inspectable end to end.

## 2. Product Surface

The reference product is a Genomic Research Access API with dataset catalogue, access request workflow, approval and rejection actions, structured audit events, local JWT authentication, role-based permissions, and object-level authorisation.

## 3. Security Outcomes

- 14 documented milestones completed.
- 25 product-security capabilities mapped to evidence.
- 44 canonical findings under deterministic ownership, release and lifecycle governance.
- 46 source findings preserved with source lineage.
- 178 integration lineage edges exported for downstream validation.
- 9 consolidated evidence domains verified locally.

## 4. Evidence Boundary

All assurance evidence is generated locally from repository files, local tests, local scanner wrappers, and deterministic timestamps. AWS architecture is Terraform reference code only. Repository 5 integration is a contract export only and does not modify another repository.

## 5. Architecture

Start with:

- [Application Architecture](docs/architecture/application-architecture.md)
- [AWS Reference Architecture](docs/architecture/aws-reference-architecture.md)
- [Portfolio Diagrams](docs/architecture/diagrams/system-context.md)
- [Product Security Operating Model](docs/portfolio/product-security-operating-model.md)

## 6. Secure SDLC

The secure SDLC is represented as runnable local commands, policy files, CI workflows and generated evidence. The final validation target is:

```bash
make final-validation
```

## 7. Threat Modelling

STRIDE threat model artefacts live under [docs/threat-model](docs/threat-model/README.md). They include assets, actors, trust boundaries, data flows, threat register, requirements, traceability and residual risk.

## 8. API Security

Authentication, authorisation, object access, security headers, CORS and audit behaviour are covered by local tests and evidence under `outputs/security/api-security/`.

## 9. Infrastructure Security

Terraform under [infrastructure](infrastructure/README.md) models ECS Fargate, ALB, VPC, DynamoDB, KMS, Secrets Manager metadata, ECR, CloudTrail and observability controls. It is intentionally not applied.

## 10. AppSec Pipeline

Milestone 5 added Gitleaks, Semgrep, Bandit, pip-audit, CycloneDX SBOM, Checkov, Docker image build validation and Trivy container scanning through pinned wrappers and governed evidence.

## 11. Dynamic Security

Dynamic validation includes local pytest boundary tests, Schemathesis OpenAPI checks and OWASP ZAP local scans. Dynamic targets are restricted to localhost and approved local Docker usage.

## 12. Findings Management

Scanner, threat-model, infrastructure and dynamic findings are normalised into canonical findings with deterministic IDs, owners, SLAs, risk scores and suppression governance.

## 13. Release Assurance

Release gates evaluate canonical findings and produce deterministic decisions, rule evaluations, approvals and action lists. Current local decision is `conditional_pass`.

## 14. Vulnerability Lifecycle

Lifecycle governance provides triage states, exception approval, expiry handling, verification-before-closure and audit reports. It is local and does not integrate with ticketing systems.

## 15. Evidence And Reporting

Consolidated evidence lives under `outputs/security/evidence/`. Reports live under `reports/security/` and `reports/portfolio/`.

## 16. Developer Enablement

Developer guidance, security checklists and local workflow instructions live under [docs/developer-security](docs/developer-security/README.md).

## 17. Security Champions

The Security Champions programme lives under [security-champions](security-champions/README.md), including charter, roles, workshops, exercises, metrics and continuity guidance.

## 18. Repository Integration Contract

The Repository 5 contract export lives under [docs/integration](docs/integration/README.md) and `outputs/security/integration/`. It is compatible, versioned and validated locally, but performs no live ingestion.

## 19. Portfolio Documentation

Recruiter, engineering manager and security reviewer views are under [docs/portfolio](docs/portfolio/project-case-study.md). Start with:

- [Project Case Study](docs/portfolio/project-case-study.md)
- [Executive Case Study](docs/portfolio/executive-case-study.md)
- [Technical Case Study](docs/portfolio/technical-case-study.md)
- [Interview Talking Points](docs/portfolio/interview-talking-points.md)
- [CV Bullets](docs/portfolio/cv-bullets.md)

## 20. Portfolio Evidence

Generate portfolio evidence and reports:

```bash
make portfolio-full
```

Key outputs:

- `outputs/security/portfolio/portfolio-summary.json`
- `outputs/security/portfolio/security-capability-matrix.json`
- `outputs/security/portfolio/portfolio-manifest.json`
- `outputs/portfolio/`
- `reports/portfolio/`

## 21. Local Setup

Requires Python 3.11 or later.

```bash
make setup
make run
```

Open `http://127.0.0.1:8000/docs` for the local OpenAPI UI.

## 22. Quality Gates

```bash
make format-check
make lint
make type-check
make test-coverage
make quality
```

## 23. Security Gates

```bash
make appsec-full
make dynamic-full
make findings-full
make release-full
make lifecycle-full
make evidence-full
make integration-full
make security-assurance-full
```

## 24. Final Validation

```bash
make final-validation
git diff --check
git status --short
```

`final-validation` verifies quality, existing evidence manifests, integration evidence and portfolio evidence. Docker-backed AppSec commands remain separate because they depend on local Docker availability.

## 25. Governance

Repository governance is documented in `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and [.github/repository-metadata.md](.github/repository-metadata.md).

## 26. Limitations

The repository intentionally excludes production deployment, AWS resource creation, live identity-provider integration, ticketing integrations, dashboards, messaging integrations, regulatory certification and changes to Repository 5. See [limitations and residual risk](docs/portfolio/limitations-and-residual-risk.md).
