"""Dataset repository."""

from genomic_research_access_api.domain.models import Dataset


class DatasetRepository:
    def __init__(self, datasets: list[Dataset]) -> None:
        self._datasets = {dataset.dataset_id: dataset for dataset in datasets}

    def list(self) -> list[Dataset]:
        return sorted(self._datasets.values(), key=lambda dataset: dataset.dataset_id)

    def get(self, dataset_id: str) -> Dataset | None:
        return self._datasets.get(dataset_id)
