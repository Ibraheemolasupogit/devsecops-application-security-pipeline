"""Cross-tool deterministic findings deduplication."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from genomic_research_access_api.security.findings.models import Finding


def deduplicate(findings: list[Finding]) -> tuple[list[Finding], dict[str, dict[str, Any]]]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[_dedupe_key(finding)].append(finding)

    primary: list[Finding] = []
    source_map: dict[str, dict[str, Any]] = {}
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda item: (item.finding_id, item.source_tool))
        winner = members[0]
        related = [item.finding_id for item in members[1:]]
        winner.related_finding_ids = sorted(set(winner.related_finding_ids + related))
        winner.metadata["deduplication_rationale"] = _rationale(key, members)
        primary.append(winner)
        source_map[winner.finding_id] = {
            "deduplication_key": key,
            "primary_finding_id": winner.finding_id,
            "source_finding_ids": [item.finding_id for item in members],
            "source_tools": sorted({item.source_tool for item in members}),
            "rationale": winner.metadata["deduplication_rationale"],
        }
    return sorted(primary, key=lambda item: item.finding_id), source_map


def _dedupe_key(finding: Finding) -> str:
    if finding.cve and finding.package_name:
        return f"cve|{finding.cve}|{finding.package_name}"
    if finding.cwe and finding.file and finding.line:
        return f"cwe-file-line|{finding.cwe}|{finding.file}|{finding.line}"
    if finding.control_ids and finding.asset_id:
        return f"control-asset|{','.join(sorted(finding.control_ids))}|{finding.asset_id}"
    return finding.deduplication_key


def _rationale(key: str, members: list[Finding]) -> str:
    if len(members) == 1:
        return "unique exact key"
    tools = ", ".join(sorted({item.source_tool for item in members}))
    return f"merged by exact key {key} across {tools}; all source records retained"
