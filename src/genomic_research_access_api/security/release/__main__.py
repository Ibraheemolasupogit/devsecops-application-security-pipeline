"""CLI for Milestone 8 release-assurance gates."""

from __future__ import annotations

import argparse
import sys

from genomic_research_access_api.security.release.config import (
    DEFAULT_AS_OF_DATE,
    DEFAULT_ENVIRONMENT,
    DEFAULT_TIMESTAMP,
)
from genomic_research_access_api.security.release.evaluator import evaluate
from genomic_research_access_api.security.release.evidence import generate, verify
from genomic_research_access_api.security.release.report import generate_reports
from genomic_research_access_api.security.release.rules import (
    approved_roles,
    validate_policy_config,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["validate", "evaluate", "evidence", "verify", "report", "full", "enforce"],
    )
    parser.add_argument("--timestamp", default=DEFAULT_TIMESTAMP)
    parser.add_argument("--as-of-date", default=DEFAULT_AS_OF_DATE)
    parser.add_argument("--environment", default=DEFAULT_ENVIRONMENT)
    parser.add_argument("--approvals-file")
    args = parser.parse_args()

    if args.command == "validate":
        summary = validate_policy_config()
        if not summary["valid"]:
            raise SystemExit("release policy validation failed")
        print(f"validated {summary['rule_count']} release gate rules")
    elif args.command == "evaluate":
        result = evaluate(
            timestamp=args.timestamp, as_of_date=args.as_of_date, environment=args.environment
        )
        decision_id = result["decision"]["decision_id"]
        decision = result["decision"]["decision"]
        print(f"evaluated release gate decision {decision_id}: {decision}")
    elif args.command == "evidence":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date, environment=args.environment)
        print("generated release evidence")
    elif args.command == "verify":
        verify()
        print("verified release evidence")
    elif args.command == "report":
        generate_reports()
        print("generated release reports")
    elif args.command == "full":
        generate(timestamp=args.timestamp, as_of_date=args.as_of_date, environment=args.environment)
        verify()
        generate_reports()
        print("completed release full workflow")
    elif args.command == "enforce":
        roles = approved_roles(args.approvals_file)
        result = evaluate(
            timestamp=args.timestamp,
            as_of_date=args.as_of_date,
            environment=args.environment,
            approval_roles=roles,
        )
        approvals = result["required_approvals"]
        print(
            f"release enforcement {result['decision']['decision_id']}: "
            f"{result['decision']['decision']}; missing approvals: "
            f"{', '.join(approvals['missing_approvals']) or 'none'}"
        )
        sys.exit(int(approvals["enforcement_exit_code"]))


if __name__ == "__main__":
    main()
