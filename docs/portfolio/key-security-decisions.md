# Key Security Decisions

- Deny by default for authenticated API access.
- Separate requester and approver duties.
- Keep AWS and Repository 5 interactions non-live.
- Treat suppressions as governed records with rationale and expiry.
- Keep release gates evaluable even when the result is conditional.
- Reject portfolio readiness when evidence paths or checksums drift.
