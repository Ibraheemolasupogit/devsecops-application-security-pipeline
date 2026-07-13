# Findings Model

The canonical finding schema is generated at `schemas/security/findings/canonical-finding.schema.json` from `src/genomic_research_access_api/security/findings/models.py`.

Each finding preserves the source tool, native source identifier, severity, confidence, evidence reference, source record hash, deduplication key, asset context, owner, SLA, risk score and suppression state.

Stable IDs use:

```text
FND-<DOMAIN>-<12_CHAR_SHA256>
```

The hash input is a documented exact key such as tool + rule + resource, CVE + package, CWE + file + line, or residual-risk ID. Absolute local paths and secret-bearing values are excluded.
