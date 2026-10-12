"""Local Terraform command wrapper that never deploys resources."""

from __future__ import annotations

import argparse
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INFRA = ROOT / "infrastructure"
EKS = INFRA / "terraform"
ENVIRONMENTS = [
    INFRA / "environments" / "dev",
    INFRA / "environments" / "prod",
    EKS / "artifacts",
    EKS / "environments" / "nonprod",
    EKS / "environments" / "prod",
    EKS / "bootstrap",
]


def _terraform() -> str | None:
    return shutil.which("terraform")


def _run(args: list[str], cwd: Path = INFRA) -> None:
    terraform = _terraform()
    if terraform is None:
        print("SKIPPED: terraform is not installed; no AWS resources were created.")
        return
    subprocess.run([terraform, *args], cwd=cwd, check=True)


def fmt(check: bool) -> None:
    args = ["fmt", "-recursive"]
    if check:
        args.append("-check")
    _run(args)


def init() -> None:
    for environment in ENVIRONMENTS:
        _run(["init", "-backend=false"], cwd=environment)


def validate() -> None:
    for environment in ENVIRONMENTS:
        _run(["init", "-backend=false"], cwd=environment)
        _run(["validate"], cwd=environment)


def test() -> None:
    # Every test uses mock_provider and command=plan; never a live provider/apply.
    for environment in [
        *ENVIRONMENTS[2:],
        *(
            EKS / "modules" / name
            for name in (
                "eks",
                "networking",
                "ecr",
                "github-oidc",
                "github-actions-role",
                "codebuild-runner",
            )
        ),
    ]:
        _run(["init", "-backend=false"], cwd=environment)
        _run(["test"], cwd=environment)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["fmt", "fmt-check", "init", "validate", "test"])
    args = parser.parse_args()
    if args.command == "fmt":
        fmt(check=False)
    elif args.command == "fmt-check":
        fmt(check=True)
    elif args.command == "init":
        init()
    elif args.command == "validate":
        validate()
    else:
        test()


if __name__ == "__main__":
    main()
