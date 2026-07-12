# Container Scanning

Container scanning uses Trivy:

```bash
make container-build-security
make container-scan
```

The wrapper uses a native `trivy` binary when present. If unavailable, it uses the pinned `aquasec/trivy:0.54.1` container image. Both the build and scan paths require a running Docker daemon locally.
