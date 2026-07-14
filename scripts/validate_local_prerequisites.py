"""Validate local developer security prerequisites."""

from __future__ import annotations

from genomic_research_access_api.security.enablement.evidence import prerequisite_summary

if __name__ == "__main__":
    result = prerequisite_summary()
    print(f"local prerequisite status: {result['overall_status']}")
