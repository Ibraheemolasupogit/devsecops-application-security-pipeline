"""Deterministic lifecycle audit history helpers."""

from __future__ import annotations

from typing import Any

from genomic_research_access_api.security.findings.identifiers import stable_hash
from genomic_research_access_api.security.lifecycle.models import HistoryEntry


def history_entry(
    *,
    vulnerability_id: str,
    event_type: str,
    actor_role: str,
    reason: str,
    timestamp: str,
    from_status: str | None = None,
    to_status: str | None = None,
    evidence_reference: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> HistoryEntry:
    payload = {
        "vulnerability_id": vulnerability_id,
        "event_type": event_type,
        "from_status": from_status,
        "to_status": to_status,
        "actor_role": actor_role,
        "reason": reason,
        "timestamp": timestamp,
        "evidence_reference": evidence_reference,
        "metadata": metadata or {},
    }
    return HistoryEntry(event_id="EVT-" + stable_hash(payload, length=12), **payload)
