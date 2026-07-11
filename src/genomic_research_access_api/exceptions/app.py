"""Controlled application exceptions."""

from typing import ClassVar


class ApplicationError(Exception):
    code = "APPLICATION_ERROR"
    message = "An application error occurred."
    status_code = 500
    headers: ClassVar[dict[str, str]] = {}

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.message)
        self.public_message = message or self.message


class DatasetNotFoundError(ApplicationError):
    code = "DATASET_NOT_FOUND"
    message = "The requested dataset was not found."
    status_code = 404


class AccessRequestNotFoundError(ApplicationError):
    code = "ACCESS_REQUEST_NOT_FOUND"
    message = "The requested access request was not found."
    status_code = 404


class InvalidAccessRequestTransitionError(ApplicationError):
    code = "INVALID_ACCESS_REQUEST_TRANSITION"
    message = "The access request cannot move to the requested state."
    status_code = 409


class InvalidApprovalDecisionError(ApplicationError):
    code = "INVALID_APPROVAL_DECISION"
    message = "The approval decision is invalid."
    status_code = 400


class AuthenticationRequiredError(ApplicationError):
    code = "AUTHENTICATION_REQUIRED"
    message = "Authentication is required for this endpoint."
    status_code = 401
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": "Bearer"}


class InvalidAccessTokenError(ApplicationError):
    code = "INVALID_ACCESS_TOKEN"
    message = "The supplied access token is invalid."
    status_code = 401
    headers: ClassVar[dict[str, str]] = {"WWW-Authenticate": 'Bearer error="invalid_token"'}


class AccessTokenExpiredError(InvalidAccessTokenError):
    code = "ACCESS_TOKEN_EXPIRED"
    message = "The supplied access token has expired."


class InvalidTokenIssuerError(InvalidAccessTokenError):
    code = "INVALID_TOKEN_ISSUER"
    message = "The supplied access token issuer is invalid."


class InvalidTokenAudienceError(InvalidAccessTokenError):
    code = "INVALID_TOKEN_AUDIENCE"
    message = "The supplied access token audience is invalid."


class InsufficientPermissionError(ApplicationError):
    code = "INSUFFICIENT_PERMISSION"
    message = "The authenticated principal does not have permission for this action."
    status_code = 403


class ObjectAccessDeniedError(ApplicationError):
    code = "OBJECT_ACCESS_DENIED"
    message = "The requested resource was not found."
    status_code = 404


class SeparationOfDutiesViolationError(ApplicationError):
    code = "SEPARATION_OF_DUTIES_VIOLATION"
    message = "The requester cannot approve or reject their own access request."
    status_code = 403
