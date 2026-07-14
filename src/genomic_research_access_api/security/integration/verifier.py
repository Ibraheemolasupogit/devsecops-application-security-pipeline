"""Verification wrapper for integration evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from genomic_research_access_api.security.integration.config import OUTPUT_DIR
from genomic_research_access_api.security.integration.validator import validate_export


def verify(output_dir: Path = OUTPUT_DIR) -> dict[str, Any]:
    summary = validate_export(output_dir)
    if not summary["valid"]:
        raise ValueError(summary["errors"])
    return summary
