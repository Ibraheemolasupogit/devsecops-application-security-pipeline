"""Deterministic synthetic dataset seed data."""

from datetime import UTC, datetime

from genomic_research_access_api.domain.enums import (
    AccessLevel,
    DatasetStatus,
    SensitivityClassification,
)
from genomic_research_access_api.domain.models import Dataset

SEED_TIMESTAMP = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)


def synthetic_datasets() -> list[Dataset]:
    """Return stable, non-identifiable catalogue data."""

    return [
        Dataset(
            dataset_id="syn-rare-disease-001",
            name="Synthetic Rare Disease Cohort Summary",
            description="Deterministic aggregate metadata for simulated rare disease studies.",
            research_domain="rare disease research",
            sensitivity_classification=SensitivityClassification.SYNTHETIC_RESTRICTED,
            access_level=AccessLevel.AGGREGATE_ANALYSIS,
            status=DatasetStatus.ACTIVE,
            created_at=SEED_TIMESTAMP,
            updated_at=SEED_TIMESTAMP,
        ),
        Dataset(
            dataset_id="syn-cancer-001",
            name="Synthetic Oncology Variant Catalogue",
            description=(
                "Synthetic cohort-level oncology variant annotations for access workflow testing."
            ),
            research_domain="cancer research",
            sensitivity_classification=SensitivityClassification.SYNTHETIC_RESTRICTED,
            access_level=AccessLevel.CONTROLLED_EXPORT,
            status=DatasetStatus.ACTIVE,
            created_at=SEED_TIMESTAMP,
            updated_at=SEED_TIMESTAMP,
        ),
        Dataset(
            dataset_id="syn-population-001",
            name="Synthetic Population Genomics Baseline",
            description=(
                "Non-identifiable population genomics summary records for demonstration use."
            ),
            research_domain="population genomics",
            sensitivity_classification=SensitivityClassification.SYNTHETIC_CONTROLLED,
            access_level=AccessLevel.METADATA_ONLY,
            status=DatasetStatus.ACTIVE,
            created_at=SEED_TIMESTAMP,
            updated_at=SEED_TIMESTAMP,
        ),
        Dataset(
            dataset_id="syn-pharmacogenomics-001",
            name="Synthetic Pharmacogenomics Response Study",
            description=(
                "Simulated aggregate pharmacogenomics study metadata without patient records."
            ),
            research_domain="pharmacogenomics",
            sensitivity_classification=SensitivityClassification.SYNTHETIC_CONTROLLED,
            access_level=AccessLevel.AGGREGATE_ANALYSIS,
            status=DatasetStatus.ACTIVE,
            created_at=SEED_TIMESTAMP,
            updated_at=SEED_TIMESTAMP,
        ),
    ]
