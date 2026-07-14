"""CLI for developer security enablement."""

from __future__ import annotations

import argparse

from genomic_research_access_api.security.enablement import evidence


def main() -> None:
    parser = argparse.ArgumentParser(description="Developer security enablement")
    parser.add_argument(
        "command",
        choices=[
            "doctor",
            "validate-docs",
            "generate-evidence",
            "verify-evidence",
            "report",
            "full",
        ],
    )
    args = parser.parse_args()
    if args.command == "doctor":
        summary = evidence.doctor()
        print(f"security doctor status: {summary['overall_status']}")
    elif args.command == "validate-docs":
        evidence.validate_docs()
        print("developer security documentation validated")
    elif args.command == "generate-evidence":
        written = evidence.generate()
        print(f"generated {len(written)} developer enablement evidence files")
    elif args.command == "verify-evidence":
        evidence.verify()
        print("verified developer enablement evidence")
    elif args.command == "report":
        written = evidence.report()
        print(f"generated {len(written)} developer enablement reports")
    else:
        evidence.doctor()
        evidence.generate()
        evidence.verify()
        evidence.report()
        evidence.validate_docs()
        print("completed developer enablement workflow")
