# Security Policy

This is a portfolio repository and is not a monitored production service.

If you identify a vulnerability or unsafe pattern in this demonstration code, open a private communication channel with the repository maintainer where available, or raise a GitHub issue that avoids publishing exploit details or real secrets.

Do not submit real patient data, NHS data, genomic data, credentials, cloud account identifiers, or sensitive operational details in reports.

Current implemented security controls include local JWT authentication, role-based and object-level authorisation, threat-model validation, non-deployed Terraform reference controls, a Milestone 5 AppSec pipeline, Milestone 6 local dynamic API security validation, Milestone 7 canonical findings normalisation, Milestone 8 local release-assurance gates, Milestone 9 vulnerability lifecycle and exception governance, and Milestone 10 consolidated security evidence reporting.

Run local security checks with:

```bash
make quality
make appsec-fast
make dynamic-fast
make findings-full
make release-full
make lifecycle-full
make evidence-full
```

Docker-backed Gitleaks, Trivy, Schemathesis and ZAP scans require a running Docker daemon when native binaries or scanner containers are used. Dynamic scan targets must remain local-only. Do not treat local scanner, findings, release, lifecycle or consolidated evidence as a production vulnerability-management programme, penetration test, deployment approval system, regulatory certification or Security Champions programme.
