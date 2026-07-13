# Resource-Consumption Controls

Milestone 6 implements a lightweight in-memory rate limiter in `src/genomic_research_access_api/security/rate_limit.py`.

The control is disabled by default and enabled for dynamic-security execution. It keys by authenticated subject when available, falls back to a sanitized client identity, bounds subject storage and returns a stable 429 response with `Retry-After` when the limit is exceeded.

This is a local portfolio control, not a distributed production quota system.
