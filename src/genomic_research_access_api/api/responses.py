"""Reusable OpenAPI response metadata."""

from typing import Any

from genomic_research_access_api.schemas.common import ErrorResponse

OpenApiResponses = dict[int | str, dict[str, Any]]

AUTHENTICATION_ERROR_RESPONSES: OpenApiResponses = {
    401: {
        "model": ErrorResponse,
        "description": "Authentication is missing, expired or invalid.",
    },
    403: {
        "model": ErrorResponse,
        "description": "The authenticated principal is not authorised for this action.",
    },
    429: {
        "model": ErrorResponse,
        "description": "The request rate limit was exceeded.",
    },
}

NOT_FOUND_RESPONSE: OpenApiResponses = {
    404: {
        "model": ErrorResponse,
        "description": "The requested resource was not found or is not visible to the principal.",
    }
}
