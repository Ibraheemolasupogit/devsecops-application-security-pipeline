"""Run the developer security doctor without installing software."""

from __future__ import annotations

from genomic_research_access_api.security.enablement.evidence import doctor

if __name__ == "__main__":
    result = doctor()
    print(f"security doctor status: {result['overall_status']}")
