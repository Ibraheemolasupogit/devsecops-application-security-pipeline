"""CLI for portfolio readiness evidence."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.portfolio.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
)
from genomic_research_access_api.security.portfolio.generator import generate
from genomic_research_access_api.security.portfolio.reporting import generate_reports
from genomic_research_access_api.security.portfolio.validator import verify


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["generate", "verify", "report", "full"])
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    args = parser.parse_args()
    if args.command == "generate":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        print("generated portfolio evidence")
    elif args.command == "verify":
        result = verify()
        if not result["valid"]:
            raise SystemExit(result["errors"])
        print("verified portfolio evidence")
    elif args.command == "report":
        generate_reports()
        print("generated portfolio reports")
    elif args.command == "full":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        generate_reports()
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        result = verify()
        if not result["valid"]:
            raise SystemExit(result["errors"])
        generate_reports()
        print("completed portfolio full workflow")
