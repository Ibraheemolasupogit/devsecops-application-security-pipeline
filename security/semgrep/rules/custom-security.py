import logging
import subprocess

import jwt

logger = logging.getLogger(__name__)


def AccessRequestCreate(**kwargs: object) -> dict[str, object]:
    return kwargs


def insecure_requester(payload: object) -> object:
    # ruleid: no-client-controlled-requester-id
    return AccessRequestCreate(dataset_id=payload.dataset_id, requester_id=payload.requester_id)


def secure_requester(payload: object, principal: object) -> object:
    # ok: no-client-controlled-requester-id
    return AccessRequestCreate(dataset_id=payload.dataset_id, requester_id=principal.subject)


def insecure_authorization_log(request: object) -> None:
    # ruleid: no-raw-authorization-header-logging
    logger.warning("auth=%s", request.headers.get("Authorization"))


def secure_authorization_log() -> None:
    # ok: no-raw-authorization-header-logging
    logger.warning("authorization header present")


def insecure_jwt_decode(token: str, key: str) -> dict[str, object]:
    # ruleid: jwt-decode-must-pin-algorithms
    return jwt.decode(token, key)


def secure_jwt_decode(token: str, key: str) -> dict[str, object]:
    # ok: jwt-decode-must-pin-algorithms
    return jwt.decode(token, key, algorithms=["RS256"])


def insecure_shell(command: str) -> None:
    # ruleid: no-subprocess-shell-true
    subprocess.run(command, shell=True, check=True)


def secure_shell(command: list[str]) -> None:
    # ok: no-subprocess-shell-true
    subprocess.run(command, shell=False, check=True)
