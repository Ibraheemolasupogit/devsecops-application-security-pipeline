# Consumer Validation Guide

A consumer control plane can validate and ingest the bundle by:

1. Loading `integration-manifest.json`.
2. Checking contract name and supported version.
3. Verifying all output checksums.
4. Validating finding records against the schema.
5. Checking required fields, duplicate IDs, record counts and lineage edges.
6. Rejecting local paths, secrets, private keys, JWTs and personal email addresses.

The local example is in `examples/integration-consumer/`.

