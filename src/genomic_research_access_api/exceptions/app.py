"""Controlled application exceptions."""


class ApplicationError(Exception):
    code = "APPLICATION_ERROR"
    message = "An application error occurred."
    status_code = 500

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
