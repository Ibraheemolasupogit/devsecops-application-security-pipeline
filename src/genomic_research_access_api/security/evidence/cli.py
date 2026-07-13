"""CLI for consolidated security evidence."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.evidence.aggregation import aggregate, generate
from genomic_research_access_api.security.evidence.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    evidence_as_of_date,
    evidence_timestamp,
)
from genomic_research_access_api.security.evidence.discovery import validate_source_registry
from genomic_research_access_api.security.evidence.reporting import generate_reports
from genomic_research_access_api.security.evidence.verification import verify, verify_sources


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "discover",
            "validate-sources",
            "aggregate",
            "generate",
            "verify",
            "report",
            "full",
        ],
    )
    parser.add_argument("--timestamp", default=evidence_timestamp(DEFAULT_TIMESTAMP))
    parser.add_argument("--as-of-date", default=evidence_as_of_date(DEFAULT_AS_OF_DATE))
    args = parser.parse_args()
    if args.command == "discover":
        summary = validate_source_registry()
        if not summary["valid"]:
            raise SystemExit(summary["errors"])
        print(f"discovered {summary['source_count']} evidence sources")
    elif args.command == "validate-sources":
        summary = verify_sources()
        if not summary["valid"]:
            raise SystemExit(summary)
        print(f"validated {summary['verified_domains']} evidence sources")
    elif args.command == "aggregate":
        evidence, validation = aggregate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        if not validation["valid"]:
            raise SystemExit(validation["errors"])
        print(f"aggregated evidence bundle {evidence.evidence_bundle_id}")
    elif args.command == "generate":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        print("generated consolidated evidence")
    elif args.command == "verify":
        verify()
        print("verified consolidated evidence")
    elif args.command == "report":
        generate_reports()
        print("generated consolidated evidence reports")
    elif args.command == "full":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        verify()
        generate_reports()
        print("completed consolidated evidence full workflow")


if __name__ == "__main__":
    main()
