# Milestone 3

Milestone 3 implements local authentication, authorisation and API-security controls for the Genomic Research Access API.

Delivered:

- RS256 JWT validation for protected API routes.
- Central `AuthenticatedPrincipal` model.
- Deny-by-default role-to-permission matrix.
- Object-level authorisation for access requests and restricted dataset detail.
- Separation of requester and approver duties.
- Mass-assignment protection for requester identity.
- Security headers, explicit CORS checks and safe correlation ID handling.
- Security audit events for authentication success/failure, authorisation denial, object views and self-approval denial.
- Deterministic API-security evidence and generated reports.

Explicitly not delivered:

- External OIDC or JWKS integration.
- Durable policy, entitlement or audit storage.
- Production rate limiting.
- AWS resources.
- Terraform.
- AppSec scanners.
- Release gates.
- Vulnerability lifecycle workflows.
- Deployment.
