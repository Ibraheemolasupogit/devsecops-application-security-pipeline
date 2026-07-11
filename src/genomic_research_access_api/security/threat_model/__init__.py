"""Threat-model validation and evidence generation."""

from genomic_research_access_api.security.threat_model.validation import (
    ThreatModelValidationError,
    validate_threat_model,
)

__all__ = ["ThreatModelValidationError", "validate_threat_model"]
