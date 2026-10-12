# Kubernetes workload model

This directory contains an offline Kustomize model, not a deployment. The application has a shared [base](base/) and two small overlays:

- [QA](overlays/qa/): namespace `qa` on the shared non-production EKS cluster.
- [Production](overlays/prod/): namespace `production` on the separate production EKS cluster.

Use `kubectl kustomize kubernetes/overlays/qa` and `kubectl kustomize kubernetes/overlays/prod` to inspect rendered output. Repository checks are `make k8s-render`, `make k8s-validate`, `make k8s-security`, `make k8s-test`, and `make k8s-full`. They use local Kustomize rendering, parsed manifest tests and Checkov; none contacts a cluster.

The image is intentionally an ECR `@sha256:` placeholder. M6 supplies the exact immutable digest; M10 uses that same digest for production. Do not replace it with `latest` or an environment tag. The `api-identity` Secret is referenced but never defined here. M8 will connect its approved external source and synchronization path.

The production overlay is not ready for deployment of state-changing requests: access requests and audit events are currently held in per-process memory and will diverge across replicas. `/health` reports process health only. NetworkPolicy enforcement also remains to be enabled and tested on the selected EKS networking dataplane. See [workload architecture](../docs/architecture/kubernetes-workload-model.md) and [security controls](../docs/engineering/kubernetes-security-controls.md).
