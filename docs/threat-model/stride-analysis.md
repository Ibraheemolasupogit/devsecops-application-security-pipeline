# STRIDE Analysis

The authoritative threat classification is `threat-register.yaml`.

Material STRIDE themes:

- Spoofing: missing production authentication and future stolen identities.
- Tampering: request manipulation, workflow state manipulation, log injection and supply-chain artefact alteration.
- Repudiation: missing or altered audit records, correlation ID abuse and stale security review.
- Information disclosure: dataset metadata, audit events, Terraform state, future storage and hardcoded credentials.
- Denial of service: resource exhaustion and unbounded request volume.
- Elevation of privilege: broken authorisation, overprivileged identities and container/runtime compromise.
