# Local Security Workflow

Recommended local sequence:

```bash
make format
make test
make semgrep-test
make sast
make sca
make checkov-scan
make appsec-evidence
make verify-appsec-evidence
```

Run Docker-backed checks when Docker is available:

```bash
make secrets-scan
make container-build-security
make container-scan
```

Regenerate reports with:

```bash
make appsec-report
```
