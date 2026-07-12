# Security Policy

This is a portfolio repository and is not a monitored production service.

If you identify a vulnerability or unsafe pattern in this demonstration code, open a private communication channel with the repository maintainer where available, or raise a GitHub issue that avoids publishing exploit details or real secrets.

Do not submit real patient data, NHS data, genomic data, credentials, cloud account identifiers, or sensitive operational details in reports.

Current implemented security controls include local JWT authentication, role-based and object-level authorisation, threat-model validation, non-deployed Terraform reference controls, and a Milestone 5 AppSec pipeline.

Run local security checks with:

```bash
make quality
make appsec-fast
```

Docker-backed Gitleaks and Trivy scans require a running Docker daemon when native binaries are not installed. Do not treat local scanner evidence as a production vulnerability-management programme or release approval gate.
