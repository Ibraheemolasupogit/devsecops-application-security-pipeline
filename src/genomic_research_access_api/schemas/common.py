"""Shared API schemas."""

from pydantic import BaseModel, ConfigDict


class ApiModel(BaseModel):
    model_config = ConfigDict(use_enum_values=True, str_strip_whitespace=True)


class ErrorBody(ApiModel):
    code: str
    message: str
    correlation_id: str


class ErrorResponse(ApiModel):
    error: ErrorBody
