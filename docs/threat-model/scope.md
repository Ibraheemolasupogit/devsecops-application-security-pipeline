# Scope

## System Purpose

The system demonstrates a secure-design foundation for a synthetic healthcare research access workflow.

## Current Implementation Scope

In scope:

- Local FastAPI service.
- Synthetic dataset metadata.
- Access request submission, retrieval, approval and rejection.
- Local RS256 JWT authentication.
- Role-based and object-level authorisation.
- Structured audit events.
- Local Makefile and CI validation.
- Dockerfile and pinned dependencies.

## Anticipated Deployment Scope

Future analysis considers a production-style cloud-native deployment, including identity provider integration, runtime identities, cloud datastore, logging service, container registry, CI/CD deployment identity and infrastructure definitions.

## Sensitive and Non-Sensitive Data

The dataset catalogue is synthetic and non-identifiable. Access requests and audit events are security-relevant and treated as sensitive for workflow integrity even though they contain no real patient or genomic data.

## Assumptions

- All data is synthetic.
- The repository contains no real patient or genomic data.
- No AWS account, Terraform state or cloud deployment exists.
- Current authentication uses synthetic local JWT keys only.

## Exclusions

External IdP integration, durable policy storage, AWS resources, Terraform, AppSec scanners, release gates and vulnerability lifecycle features are excluded from Milestone 3.
