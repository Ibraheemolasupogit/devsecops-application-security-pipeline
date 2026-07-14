"""CLI for the Repository 5 integration contract export."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.integration.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
    evidence_timestamp,
    integration_as_of_date,
)
from genomic_research_access_api.security.integration.exporter import generate_bundle
from genomic_research_access_api.security.integration.reporting import generate_reports
from genomic_research_access_api.security.integration.validator import (
    validate_export,
    validate_policy,
)
from genomic_research_access_api.security.integration.verifier import verify


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["validate-policy", "export", "validate-export", "verify", "report", "full"],
    )
    parser.add_argument("--timestamp", default=evidence_timestamp(DEFAULT_TIMESTAMP))
    parser.add_argument("--as-of-date", default=integration_as_of_date(DEFAULT_AS_OF_DATE))
    args = parser.parse_args()
    if args.command == "validate-policy":
        summary = validate_policy()
        if not summary["valid"]:
            raise SystemExit(summary["errors"])
        print("validated integration policy")
    elif args.command == "export":
        generate_bundle(timestamp=args.timestamp, as_of_date=args.as_of_date)
        print("generated integration export bundle")
    elif args.command == "validate-export":
        summary = validate_export()
        if not summary["valid"]:
            raise SystemExit(summary["errors"])
        print("validated integration export")
    elif args.command == "verify":
        verify()
        print("verified integration evidence")
    elif args.command == "report":
        generate_reports()
        print("generated integration reports")
    elif args.command == "full":
        policy = validate_policy()
        if not policy["valid"]:
            raise SystemExit(policy["errors"])
        generate_bundle(timestamp=args.timestamp, as_of_date=args.as_of_date)
        summary = validate_export()
        if not summary["valid"]:
            raise SystemExit(summary["errors"])
        verify()
        generate_reports()
        print("completed integration full workflow")


if __name__ == "__main__":
    main()
