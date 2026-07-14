# Limitations

- This is not a production genomics platform.
- This repository is not affiliated with or endorsed by Genomics England.
- All data is synthetic, deterministic, and non-identifiable.
- Runtime state is stored in memory and resets on restart.
- Local JWT keys under `tests/fixtures/keys/` are synthetic development material and are not production secrets.
- The audit event API is for local demonstration only and is restricted by role.
- External identity-provider integration, AWS deployment, distributed production rate limiting and immutable audit-log operations are intentionally deferred.
- AWS Terraform is present as a reference architecture only; no resources are deployed.
- Terraform validation is skipped locally when Terraform is unavailable and is configured for CI through a pinned setup action.
- Gitleaks and Trivy local execution require native binaries or a running Docker daemon for pinned container fallbacks.
- Schemathesis and ZAP dynamic scans require Docker for pinned scanner containers and are restricted to local targets.
- Checkov findings are captured as reporting evidence in Milestone 5; full Terraform remediation is not claimed.
- Dynamic API security evidence is local synthetic validation and is not penetration-test coverage.
- Findings normalisation uses demonstration risk, ownership and SLA values. Milestone 8 release gates consume those findings for deterministic local release-assurance evidence.
- Milestone 9 lifecycle evidence demonstrates vulnerability lifecycle and exception governance locally. It is not a production ticketing system, live deployment approval system or Security Champions programme.
- Milestone 10 consolidated evidence and reports are local portfolio evidence. They are not regulatory certification, production assurance, external reporting, dashboards or monitoring.
- Milestone 12 Security Champions evidence uses synthetic role-based programme data. It is not a real attendance system, external messaging workflow, ticketing integration, dashboard or deployment.
- Milestone 13 Repository 5 integration evidence is a local export contract and sample validation bundle only. It does not modify Repository 5, access a live consumer, create APIs, queues, dashboards, external transfers, AWS resources or deployment.
