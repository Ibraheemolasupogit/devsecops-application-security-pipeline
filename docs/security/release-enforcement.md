# Release Enforcement

Evidence mode succeeds for `pass`, `warn`, `conditional_pass` and `block`.

Enforcement mode is explicit:

```bash
python -m genomic_research_access_api.security.release enforce
```

Exit code behavior:

- `0`: pass, warn, or conditional pass with all required approvals.
- `1`: conditional pass with missing approvals.
- `2`: block.

No deployment, AWS resource creation, image push or artefact signing is performed.
