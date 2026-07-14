"""CLI for Security Champions programme evidence."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.champions import evidence, reporting
from genomic_research_access_api.security.champions.inventory import validate_programme
from genomic_research_access_api.security.champions.metrics import champion_metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Security Champions programme")
    parser.add_argument(
        "command",
        choices=[
            "validate-policy",
            "metrics",
            "generate-evidence",
            "verify-evidence",
            "report",
            "full",
        ],
    )
    args = parser.parse_args()
    if args.command == "validate-policy":
        validate_programme()
        print("validated Security Champions programme policy")
    elif args.command == "metrics":
        metrics = champion_metrics()
        print(
            "calculated Security Champions metrics: "
            f"{metrics['champion_coverage_percentage']}% coverage"
        )
    elif args.command == "generate-evidence":
        written = evidence.generate()
        print(f"generated {len(written)} Security Champions evidence files")
    elif args.command == "verify-evidence":
        evidence.verify()
        print("verified Security Champions evidence")
    elif args.command == "report":
        written = reporting.generate_reports()
        print(f"generated {len(written)} Security Champions reports")
    elif args.command == "full":
        validate_programme()
        evidence.generate()
        evidence.verify()
        reporting.generate_reports()
        print("completed Security Champions workflow")


if __name__ == "__main__":
    main()
