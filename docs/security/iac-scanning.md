# IaC Scanning

IaC scanning uses Checkov against `infrastructure/`.

```bash
make checkov-scan
make iac-scan
```

Milestone 5 records Checkov findings as AppSec evidence. The current Terraform reference architecture is not deployed, and the remaining Checkov findings are not suppressed or claimed as remediated.
