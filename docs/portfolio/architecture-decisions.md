# Architecture Decisions

1. Keep the product small so the security system is reviewable.
2. Use deterministic timestamps and checksums for evidence.
3. Preserve native scanner outputs while normalising downstream findings.
4. Model AWS as Terraform reference architecture without applying it.
5. Export Repository 5 data through a contract instead of writing externally.
6. Prefer `ready_with_limitations` over overstating production readiness.
