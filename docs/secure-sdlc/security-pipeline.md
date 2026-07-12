# Security Pipeline

The local security pipeline is Makefile-driven so developers can run the same checks advertised by CI.

```mermaid
flowchart TD
    Change["Code, dependency, Dockerfile or Terraform change"] --> Local["make appsec-fast"]
    Local --> PR["Pull request"]
    PR --> AppSec["AppSec workflow"]
    PR --> Container["Container security workflow"]
    PR --> Terraform["Terraform security workflow"]
    AppSec --> Evidence["outputs/security/appsec"]
    Container --> Evidence
    Terraform --> Evidence
    Evidence --> Reports["reports/security"]
```

Core commands:

```bash
make security-tools
make semgrep-test
make sast
make sca
make checkov-scan
make appsec-evidence
make verify-appsec-evidence
make appsec-report
```

Docker-backed commands:

```bash
make secrets-scan
make container-build-security
make container-scan
```
