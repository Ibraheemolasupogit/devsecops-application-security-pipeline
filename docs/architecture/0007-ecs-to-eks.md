# 7. Select EKS for the DevSecOps Delivery Evolution

Status: accepted for target architecture; implementation deferred. Date: 2026-10-10.

Numbering follows decisions 1–6 in [Architecture Decisions](../portfolio/architecture-decisions.md). Those entries are short numbered statements, not formal ADR files; this record preserves their sequence/title style and adds the requested context and consequences.

## Context

The completed reference contains a synthetic FastAPI API, non-applied ECS/Fargate Terraform, local scanners and a rich findings/release/lifecycle/evidence operating model. There is no running ECS service or production data migration. The next programme intentionally demonstrates production-grade Kubernetes delivery on AWS; moving orchestration must preserve security engineering rather than replace it with deploy scripts.

## Decision

Select Amazon EKS with managed EC2 node groups as the target runtime. Use one shared non-production cluster and one separate production cluster when operational environments are enabled. Use Kustomize for application packaging, environment-specific GitHub OIDC roles, workload identity and immutable ECR digest promotion. Keep the ECS implementation unchanged in M1 as a documented, non-deployed reference alternative.

## Why EKS for this project

EKS enables explicit Kubernetes service accounts/RBAC, namespace quotas/network policies, deployment/probe/disruption controls, declarative environment overlays, controller integration for secrets/ingress and runtime admission/security assurance. These provide relevant platform-engineering demonstrations beyond the current single-service ECS blueprint. Selection is driven by the programme's EKS objective and the desire to test Kubernetes delivery boundaries, not by an assertion of universal superiority.

## Why ECS Fargate remains valid

The API does not intrinsically require Kubernetes. ECS Fargate supports private tasks, workload IAM, immutable images, ALB, managed capacity and rollback with fewer controllers and no Kubernetes upgrade burden. For a small real service whose team does not need Kubernetes capabilities, ECS Fargate may offer the better operational/cost fit. It remains the principal alternative, not an insecure predecessor.

## Operational and cost trade-offs

EKS adds a recurring control-plane charge, worker/EBS capacity, patching, scheduling/IP planning, add-on compatibility, RBAC/admission ownership and cluster upgrade/recovery work. Managed control plane does not manage application availability. Controllers and telemetry consume baseline capacity. Namespace isolation is not a hard cluster/account boundary. Do not claim EKS is cheaper; cost depends on uptime, utilisation, networking and telemetry retention. [AWS pricing](https://aws.amazon.com/eks/pricing/).

## Migration implications

Create separate future EKS composition/state; do not mutate or apply the ECS reference. Reuse security intent and reviewed cloud building blocks, not ECS trust policies or task security groups blindly. Add durable persistence and production authentication before production promotion. Replace task healthcheck/circuit-breaker semantics with readiness/startup/liveness, bounded rollout and tested rollback. Validate node architecture against image platform. No stateful application volume migration exists today.

## Security implications

Separate CI federation from workload federation; no static AWS keys in CI or Pod specifications. Bound deploy roles to environment/namespace and protect production approvals; controllers receive separate roles. Enforce non-root/read-only/capability-drop settings, restricted Pod security, deny-by-default networking and node metadata restrictions. Extend threat registers for Kubernetes API, node compromise, controller privileges, secrets replication and artifact substitution. Preserve object authorisation, canonical risk, exceptions and evidence verification as release gates.

## Disposition of ECS reference

Retain files/tests/evidence as historical reference during migration. In M2 define a clearly labelled reference path and active EKS path without breaking current verifiers. Only archive/move ECS later with updated scanners, documentation and contract parity. Do not run two active production platforms or delete the alternative merely to simplify the portfolio. No ECS resources need destruction because none were deployed by this repository.

## Alternatives considered

1. Continue ECS Fargate: strongest simplicity alternative; does not meet the EKS-centred learning/delivery objective.
2. EKS on Fargate: fewer worker operations, but constraints around agents/controllers/runtime controls need review; not selected for this programme's node/runtime assurance scope.
3. Self-managed Kubernetes: adds control-plane operations without sufficient project benefit.
4. One cluster for QA and production: saves baseline cost but weakens failure/change isolation; not recommended.
5. More clusters per development branch: unjustified cost/operations for one application; use bounded non-prod namespaces.

## Consequences

Positive: one coherent Kubernetes delivery model, inspectable isolation/identity controls, exact digest promotion and retained Product Security lineage. Negative: higher operational ownership and baseline cost. Acceptance requires independently testable migration milestones, cost/destroy discipline and proof that policy/evidence apply to the exact deployed candidate. This ADR is not evidence of deployment or production readiness.
