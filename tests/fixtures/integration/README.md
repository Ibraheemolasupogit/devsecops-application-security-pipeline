# Integration Validation Fixtures

The integration tests create fixture variants from the deterministic export bundle at
runtime:

- missing manifest
- tampered checksum
- unsupported contract version
- duplicate export ID
- duplicate finding ID
- invalid lifecycle status
- invalid owner
- missing required field
- metric mismatch
- lineage mismatch
- secret-bearing record
- local-path record
- CSV formula injection

