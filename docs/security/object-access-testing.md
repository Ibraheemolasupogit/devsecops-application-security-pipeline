# Object-Access Testing

`make object-access-test` validates object-level authorisation at runtime.

The dynamic test proves that a researcher can read their own access request, cannot read another researcher's request, lists only their own requests, receives the same not-found style for unauthorised and nonexistent objects, and can access restricted dataset detail only after approval.

Evidence is written to `outputs/security/dynamic/object-access-summary.json`.
