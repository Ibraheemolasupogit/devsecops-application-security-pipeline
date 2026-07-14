# Integration Consumer Validation Example

This example demonstrates how a consumer control plane can validate the exported
product-security bundle before ingestion.

It does not implement Repository 5, open a network connection, create cloud
resources, or modify another repository.

Run from the repository root:

```bash
python examples/integration-consumer/validate_bundle.py outputs/security/integration
```

