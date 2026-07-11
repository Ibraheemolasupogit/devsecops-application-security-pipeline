"""CLI entry point for threat-model validation."""

import sys

from genomic_research_access_api.security.threat_model.validation import (
    ThreatModelValidationError,
    validate_threat_model,
)


def main() -> None:
    try:
        model = validate_threat_model()
    except ThreatModelValidationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    print(
        "Threat model validation passed: "
        f"{len(model.threats)} threats, {len(model.requirements)} requirements"
    )


if __name__ == "__main__":
    main()
