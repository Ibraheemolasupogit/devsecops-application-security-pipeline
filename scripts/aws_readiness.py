"""Read-only local AWS activation prerequisite and identity check."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

REQUIRED_TERRAFORM = "1.16.5"


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def main() -> int:
    blockers: list[str] = []
    terraform = shutil.which("terraform")
    if terraform is None:
        print("terraform: missing")
        blockers.append("Terraform 1.16.5 is required")
    else:
        result = run(terraform, "version", "-json")
        try:
            version = json.loads(result.stdout)["terraform_version"]
        except (json.JSONDecodeError, KeyError):
            version = "unknown"
        state = "ready" if version == REQUIRED_TERRAFORM else "installed_but_version_mismatch"
        print(f"terraform: {state} ({version}; required {REQUIRED_TERRAFORM})")
        if version != REQUIRED_TERRAFORM:
            blockers.append(f"Terraform {version} does not match {REQUIRED_TERRAFORM}")

    for name, command, required in (
        ("aws", ("--version",), True),
        ("kubectl", ("version", "--client"), True),
        ("docker", ("version", "--format", "{{.Client.Version}}/{{.Server.Version}}"), True),
        ("docker buildx", ("buildx", "version"), True),
        ("gh", ("--version",), False),
    ):
        executable = shutil.which("docker" if name.startswith("docker") else name)
        if executable is None:
            print(f"{name}: missing" + (" (required)" if required else " (optional)"))
            if required:
                blockers.append(f"{name} is required for the corresponding activation stage")
            continue
        result = run(executable, *command)
        summary = (result.stdout or result.stderr).strip().splitlines()
        if result.returncode:
            status = "installed_but_unavailable"
            print(f"{name}: {status} ({summary[-1] if summary else 'command failed'})")
            if required:
                blockers.append(f"{name} is installed but its required runtime is unavailable")
        else:
            print(f"{name}: ready ({summary[0] if summary else 'available'})")

    aws = shutil.which("aws")
    if aws is None:
        print("AWS identity: requires_authentication (AWS CLI missing; no identity queried)")
        blockers.append("AWS CLI is missing; identity/account/region cannot be verified")
    else:
        identity = run(aws, "sts", "get-caller-identity", "--output", "json")
        if identity.returncode:
            print("AWS identity: requires_authentication (read-only STS check failed)")
            blockers.append("No valid AWS CLI session was established")
        else:
            try:
                details = json.loads(identity.stdout)
            except json.JSONDecodeError:
                print("AWS identity: unavailable (STS response was not valid JSON)")
                blockers.append("Could not parse read-only STS identity")
            else:
                print(
                    "AWS identity: authenticated "
                    f"account={details.get('Account', 'unknown')} "
                    f"principal={details.get('Arn', 'unknown')}"
                )
        region = run(aws, "configure", "get", "region")
        configured_region = region.stdout.strip() if region.returncode == 0 else ""
        print(f"AWS CLI configured region: {configured_region or 'unset'}")
        if not configured_region:
            blockers.append("AWS CLI region is unset; approved region remains a required input")

    print("AWS resource changes: none (local version checks and read-only identity commands only)")
    if blockers:
        print("Readiness: blocked")
        for blocker in blockers:
            print(f"- {blocker}")
        return 1
    print(
        "Readiness: tools and read-only identity available; region/account approval still required"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
