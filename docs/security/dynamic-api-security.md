# Dynamic API Security

Dynamic security validation targets only the local Genomic Research Access API.

Primary commands:

```bash
make dynamic-fast
make schemathesis-test
make zap-baseline
make dynamic-full
```

All scanner targets are validated before execution. Public IPs, arbitrary hostnames and external services are rejected. Raw outputs are written to `outputs/security/dynamic/raw/`; deterministic summaries and checksums are written to `outputs/security/dynamic/`.

The dynamic policy blocks unexpected 5xx responses, auth bypass, authorisation bypass, object-access bypass, schema mismatch, missing required security headers, CORS wildcard behaviour, rate-limit bypass and high-risk ZAP alerts.
