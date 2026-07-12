# Secret Scanning

Secret scanning is configured through `.gitleaks.toml` and `security/config/suppressions.yaml`.

`make secrets-scan` uses a native `gitleaks` binary when present. If unavailable, it uses the pinned `zricethezav/gitleaks:v8.24.3` container image. The local container path requires Docker to be running.

The only active suppression is a synthetic test-fixture key path. It is exact-path scoped, owner-approved and expiry-bound.
