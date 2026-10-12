# Kubernetes security controls

This document describes the rendered manifests in [the Kubernetes workload model](../architecture/kubernetes-workload-model.md). Validation is offline and applies no resources.

| Boundary | Control in the workload model | Validation | Remaining condition |
| --- | --- | --- | --- |
| Image supply chain | One shared ECR `@sha256:` image contract; no mutable tag | Parsed QA/prod manifests assert the same digest-form placeholder; Checkov scans rendered output | M6 must replace placeholder with the exact scanned/published digest |
| Pod privilege | UID/GID 10001, non-root, no privilege escalation, no privileged mode, drop `ALL`, `RuntimeDefault` seccomp | Parsed Pod/container security-context assertions and Checkov | Docker daemon unavailable in this environment, so changed image could not be built here |
| Filesystem | Read-only root, read-only identity mount, bounded `/tmp` emptyDir | Parsed volume/mount assertions and Checkov | Verify image behavior and writable paths with a container runtime before deployment |
| Kubernetes API identity | Dedicated ServiceAccount; token automount disabled at account and Pod; no RBAC | Rendered ServiceAccount/Pod assertions | No AWS workload identity exists in M4 |
| Environment | QA and production namespaces, Restricted Pod Security labels; M3 keeps them on separate clusters | Overlay rendering and namespace assertions | Labels and namespaces do not equal cluster isolation; no live admission result claimed |
| Network | API ingress only from reserved ingress-system/workload-proxy selector; egress only DNS | Parsed NetworkPolicy assertions and Checkov | EKS CNI policy enforcement is not configured/tested in M4; future AWS service egress requires explicit design |
| Availability and exhaustion | Startup/readiness/liveness `/health`; requests/limits, namespace quota/LimitRange, PDB | Parsed resource, probe, selector and disruption consistency tests | `/health` does not test dependencies; sizing needs load tests; in-memory writes block production use |
| Configuration/secrets | Immutable hashed ConfigMap for non-sensitive values; external required Secret reference, no Secret manifest | Rendered objects checked for Secret resources/key material | M8 must supply/rotate the Secret; issuer values remain reserved `.invalid` placeholders |

The manifest test suite parses Kustomize output rather than grepping source YAML. Checkov runs in its Kubernetes framework against temporary rendered QA/prod files. It does not alter the repository's Terraform-only Checkov configuration or add scanner exceptions. No live API schema or admission-webhook validation is claimed.

The NetworkPolicy's selector represents a future in-cluster workload proxy. It does not select the AWS Load Balancer Controller as if that controller forwarded requests. AWS ALB-to-Pod traffic, if introduced, needs a correct CNI/security-group model and an enforcement test. NetworkPolicy does not provide general FQDN or AWS service identity policy.

The JWT verification public key is mounted from an externally managed Kubernetes Secret only as a configuration interface. M8 will define Secrets Manager → workload identity → External Secrets Operator → namespace Secret → Pod, with scope, rotation, ownership and failure behavior. Do not put signing private keys or real credentials in this repository.
