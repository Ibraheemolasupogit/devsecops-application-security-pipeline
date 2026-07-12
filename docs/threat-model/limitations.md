# Threat Model Limitations

- The current application is local and uses in-memory state.
- The data is synthetic and non-identifiable.
- Local RS256 JWT authentication and authorisation are implemented; external IdP integration is not.
- Terraform exists as a non-deployed reference architecture; no AWS resources, durable datastore or cloud logging exist.
- Milestone 5 AppSec scanners are local/CI-oriented and are not a production vulnerability-management programme.
- Future cloud deployment, rate-limit, release-gate and durable logging controls are analysed for architecture readiness but are not active protections.
- Risk ratings are qualitative and intended for portfolio traceability, not a production risk committee.
