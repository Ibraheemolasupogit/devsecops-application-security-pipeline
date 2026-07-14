"""Lineage generation for integration export records."""

from __future__ import annotations

import hashlib

from genomic_research_access_api.security.integration.models import LineageEdge


def edge(
    *,
    source_id: str,
    target_id: str,
    relationship: str,
    source_domain: str,
    target_domain: str,
    source_reference: str,
    target_reference: str,
) -> dict[str, str]:
    checksum_source = "|".join(
        [
            source_id,
            target_id,
            relationship,
            source_domain,
            target_domain,
            source_reference,
            target_reference,
        ]
    )
    record = LineageEdge(
        source_id=source_id,
        target_id=target_id,
        relationship=relationship,
        source_domain=source_domain,
        target_domain=target_domain,
        source_reference=source_reference,
        target_reference=target_reference,
        checksum=hashlib.sha256(checksum_source.encode("utf-8")).hexdigest(),
    )
    return record.model_dump(mode="json")
