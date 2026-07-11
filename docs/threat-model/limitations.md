# Threat Model Limitations

- The current application is local and uses in-memory state.
- The data is synthetic and non-identifiable.
- Local RS256 JWT authentication and authorisation are implemented; external IdP integration is not.
- No AWS resources, Terraform, durable datastore or cloud logging exist.
- No AppSec scanners are implemented in Milestone 3.
- Future cloud, scanner, rate-limit and durable logging controls are analysed for architecture readiness but are not active protections.
- Risk ratings are qualitative and intended for portfolio traceability, not a production risk committee.
