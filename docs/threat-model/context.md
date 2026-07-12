# Context

The Genomic Research Access API is a FastAPI reference application that simulates controlled access to a catalogue of synthetic research datasets.

Current implementation:

- FastAPI API service.
- Synthetic dataset catalogue.
- Access-request workflow.
- Approval and rejection operations with authenticated reviewer principals.
- Local RS256 JWT authentication and role permissions.
- Object-level checks for access requests and restricted dataset detail.
- In-memory repositories.
- Structured audit events.
- Correlation ID middleware.
- Central JSON error handling.
- Local development audit-event retrieval endpoint.

Anticipated future context:

- External identity-provider integration.
- Cloud-native runtime and datastore.
- CI/CD security controls.
- Non-deployed AWS Terraform security.
- Local/CI AppSec scanner evidence.
- Future vulnerability and release workflows.

Future cloud deployment and release controls are analysed as planned or assumed only. They are not implemented in Milestone 5.
