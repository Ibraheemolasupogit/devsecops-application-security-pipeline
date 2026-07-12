import subprocess

import jwt


def good_identity(principal: object) -> dict[str, str]:
    return {"requester_id": principal.subject}


def good_logging() -> None:
    return None


def good_jwt(token: str, key: str) -> object:
    return jwt.decode(token, key, algorithms=["RS256"], audience="app")


def good_subprocess() -> None:
    subprocess.run(["python", "--version"], check=True)
