"""Run lightweight developer enablement validation."""

from __future__ import annotations

from genomic_research_access_api.security.enablement.evidence import validate_docs

if __name__ == "__main__":
    validate_docs()
    print("developer documentation references are valid")
