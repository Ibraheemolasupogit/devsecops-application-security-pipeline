# OWASP ZAP

OWASP ZAP runs from the pinned container `ghcr.io/zaproxy/zaproxy:2.16.1`.

Milestone 6 uses the baseline passive scan only. Active destructive rules are not enabled. The scan target must be local and is validated before Docker starts. ZAP rule governance lives in `security/dynamic/zap/rules.tsv`.

Outputs:

- `outputs/security/dynamic/raw/zap-report.json`
- `outputs/security/dynamic/raw/zap-report.html`
- `outputs/security/dynamic/zap-summary.json`
- `reports/security/zap-report.md`
