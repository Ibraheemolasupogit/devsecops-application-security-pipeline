"""CLI entry point for Milestone 7 findings workflows."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.findings.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
)
from genomic_research_access_api.security.findings.evidence import generate, verify
from genomic_research_access_api.security.findings.normalizer import build, enrich, normalise
from genomic_research_access_api.security.findings.report import generate_reports
from genomic_research_access_api.security.findings.verify import validate_findings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "normalise",
            "deduplicate",
            "enrich",
            "validate",
            "evidence",
            "verify",
            "report",
            "full",
        ],
    )
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    args = parser.parse_args()

    if args.command == "normalise":
        findings = normalise(args.as_of_date)
        print(f"normalised {len(findings)} source findings")
    elif args.command == "deduplicate":
        source, deduped, _ = build(args.as_of_date)
        print(f"deduplicated {len(source) - len(deduped)} findings")
    elif args.command == "enrich":
        findings = enrich(normalise(args.as_of_date), args.as_of_date)
        print(f"enriched {len(findings)} source findings")
    elif args.command == "validate":
        source, deduped, _ = build(args.as_of_date)
        validate_findings(source, args.as_of_date)
        validate_findings(deduped, args.as_of_date)
        print(f"validated {len(deduped)} canonical findings")
    elif args.command == "evidence":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        print("generated findings evidence")
    elif args.command == "verify":
        verify()
        print("verified findings evidence")
    elif args.command == "report":
        generate_reports()
        print("generated findings reports")
    elif args.command == "full":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        verify()
        generate_reports()
        print("completed findings full workflow")


if __name__ == "__main__":
    main()
