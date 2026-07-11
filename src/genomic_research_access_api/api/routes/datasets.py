"""Dataset catalogue routes."""

from typing import Annotated

from fastapi import APIRouter, Depends

from genomic_research_access_api.api.dependencies import get_correlation_id, get_dataset_service
from genomic_research_access_api.schemas.datasets import DatasetResponse
from genomic_research_access_api.services.datasets import DatasetService

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"])


@router.get("", response_model=list[DatasetResponse])
def list_datasets(
    service: Annotated[DatasetService, Depends(get_dataset_service)],
) -> list[DatasetResponse]:
    return [
        DatasetResponse.model_validate(dataset, from_attributes=True)
        for dataset in service.list_datasets()
    ]


@router.get("/{dataset_id}", response_model=DatasetResponse)
def get_dataset(
    dataset_id: str,
    service: Annotated[DatasetService, Depends(get_dataset_service)],
    correlation_id: Annotated[str, Depends(get_correlation_id)],
) -> DatasetResponse:
    dataset = service.get_dataset(dataset_id=dataset_id, correlation_id=correlation_id)
    return DatasetResponse.model_validate(dataset, from_attributes=True)
