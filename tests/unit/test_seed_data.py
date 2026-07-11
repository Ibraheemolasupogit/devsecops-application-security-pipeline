from genomic_research_access_api.data.seed import synthetic_datasets


def test_seed_data_is_deterministic() -> None:
    first = synthetic_datasets()
    second = synthetic_datasets()

    assert first == second
    assert all(dataset.dataset_id.startswith("syn-") for dataset in first)
    assert all("individual-level" not in dataset.description.lower() for dataset in first)
    assert all("synthetic" in dataset.name.lower() for dataset in first)
