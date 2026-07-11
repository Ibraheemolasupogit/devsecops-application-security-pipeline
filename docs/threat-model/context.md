# Context

The Genomic Research Access API is a FastAPI reference application that simulates controlled access to a catalogue of synthetic research datasets.

Current implementation:

- FastAPI API service.
- Synthetic dataset catalogue.
- Access-request workflow.
- Approval and rejection operations with simulated local reviewer context.
- In-memory repositories.
- Structured audit events.
- Correlation ID middleware.
- Central JSON error handling.
- Local development audit-event retrieval endpoint.

Anticipated future context:

- Production authentication and authorisation.
- Cloud-native runtime and datastore.
- CI/CD security controls.
- Future AWS and Terraform security.
- Future vulnerability and release workflows.

Future controls are analysed as planned or assumed only. They are not implemented in Milestone 2.
