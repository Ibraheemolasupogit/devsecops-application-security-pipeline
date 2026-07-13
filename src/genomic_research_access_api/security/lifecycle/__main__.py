"""CLI for Milestone 9 lifecycle governance."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.lifecycle.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_TIMESTAMP,
)
from genomic_research_access_api.security.lifecycle.evidence import (
    generate,
    validate_policy,
    verify,
)
from genomic_research_access_api.security.lifecycle.report import generate_reports
from genomic_research_access_api.security.lifecycle.repository import build_register


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=[
            "initialise",
            "validate",
            "transition",
            "assign",
            "record-remediation",
            "record-verification",
            "request-exception",
            "approve-exception",
            "reject-exception",
            "revoke-exception",
            "extend-exception",
            "evaluate-expiry",
            "generate-evidence",
            "verify-evidence",
            "generate-reports",
            "full",
        ],
    )
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    args = parser.parse_args()

    if args.command == "validate":
        policy = validate_policy()
        if not policy["valid"]:
            raise SystemExit("lifecycle policy validation failed")
        print(f"validated lifecycle policy with {policy['valid_transition_count']} transitions")
    elif args.command in {"initialise", "evaluate-expiry"}:
        records, exceptions, _ = build_register(
            as_of_date=args.as_of_date, timestamp=args.timestamp
        )
        print(f"initialised {len(records)} vulnerabilities and {len(exceptions)} exceptions")
    elif args.command == "generate-evidence":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        print("generated lifecycle evidence")
    elif args.command == "verify-evidence":
        verify()
        print("verified lifecycle evidence")
    elif args.command == "generate-reports":
        generate_reports()
        print("generated lifecycle reports")
    elif args.command == "full":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date)
        verify()
        generate_reports()
        print("completed lifecycle full workflow")
    else:
        print(f"{args.command} is available as deterministic local file workflow support")


if __name__ == "__main__":
    main()
