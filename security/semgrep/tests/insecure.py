import logging
import subprocess

import jwt


def bad_identity(payload: object) -> dict[str, str]:
    return dict(requester_id=payload.requester_id)


def bad_logging(request: object) -> None:
    logging.info("token %s", request.headers["Authorization"])


def bad_jwt(token: str, key: str) -> object:
    return jwt.decode(token, key)


def bad_subprocess(command: str) -> None:
    subprocess.run(command, shell=True, check=True)
