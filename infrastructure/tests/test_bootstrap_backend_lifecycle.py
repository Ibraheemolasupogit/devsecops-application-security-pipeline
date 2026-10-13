"""Regression checks for local bootstrap followed by native S3 migration."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "infrastructure/terraform/bootstrap"


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, check=True, text=True, capture_output=True
    ).stdout


def test_initial_bootstrap_has_no_active_backend() -> None:
    for path in BOOTSTRAP.glob("*.tf"):
        if path.name == "backend.tf":
            continue  # ignored operator activation; checked separately below
        assert not re.search(r'\bbackend\s+"', path.read_text()), path
    assert "infrastructure/terraform/bootstrap/backend.tf" not in git("ls-files").splitlines()
    template = (BOOTSTRAP / "backend.tf.example").read_text()
    assert 'backend "s3" {}' in template
    assert "local-exec" not in "\n".join(path.read_text() for path in BOOTSTRAP.glob("*.tf"))


def test_post_apply_backend_activation_and_native_locking_are_documented() -> None:
    runbook = (ROOT / "docs/runbooks/nonprod-platform-activation.md").read_text()
    steps = (
        "terraform init -reconfigure",
        "terraform plan -var-file=terraform.tfvars -out=bootstrap.tfplan",
        "terraform apply bootstrap.tfplan",
        "only after the reviewed apply succeeds",
        "cp backend.tf.example backend.tf",
        "terraform init -migrate-state -backend-config=backend.hcl",
        "remote `bootstrap/terraform.tfstate` object/version",
    )
    positions = [runbook.index(step) for step in steps]
    assert positions == sorted(positions)
    backend = (BOOTSTRAP / "backend.hcl.example").read_text()
    for setting in (
        'key          = "bootstrap/terraform.tfstate"',
        "encrypt      = true",
        "kms_key_id",
        "use_lockfile = true",
    ):
        assert setting in backend
    assert "dynamodb_table" not in backend


def test_live_bootstrap_artifacts_are_ignored_and_credentials_absent() -> None:
    prefix = "infrastructure/terraform/bootstrap/"
    live = [
        prefix + name
        for name in (
            "terraform.tfvars",
            "backend.hcl",
            "backend.tf",
            "bootstrap.tfplan",
            "terraform.tfstate",
            "terraform.tfstate.backup",
            "terraform.tfstate.any-suffix",
        )
    ]
    tracked = set(git("ls-files").splitlines())
    assert tracked.isdisjoint(live)
    assert set(git("check-ignore", "--no-index", *live).splitlines()) == set(live)
    for name in ("terraform.tfvars.example", "backend.hcl.example", "backend.tf.example"):
        result = subprocess.run(
            ["git", "check-ignore", "--no-index", prefix + name], cwd=ROOT, capture_output=True
        )
        assert result.returncode == 1, name
    for path in BOOTSTRAP.iterdir():
        if path.suffix != ".tf" and not path.name.endswith(".example"):
            continue
        if path.name == "backend.tf":
            continue
        source = path.read_text()
        assert not re.search(
            r"(?im)^\s*(?:access_key|secret_key|token|aws_access_key_id|aws_secret_access_key)\s*=",
            source,
        ), path
        assert not re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", source), path


def test_fresh_local_init_validate_and_pre_bucket_plan(tmp_path: Path) -> None:
    """Exercise normal init/plan without AWS access or an existing state bucket.

    The targeted plan covers the backend and bucket creation path; the existing
    mock-provider plan covers the entire bootstrap composition. No apply runs.
    """
    terraform = shutil.which("terraform")
    plugins = BOOTSTRAP / ".terraform/providers"
    if terraform is None or not plugins.exists():
        pytest.skip("Terraform and initialized bootstrap provider cache are required")
    for path in BOOTSTRAP.glob("*.tf"):
        if path.name != "backend.tf":
            shutil.copy2(path, tmp_path / path.name)
    shutil.copy2(BOOTSTRAP / ".terraform.lock.hcl", tmp_path / ".terraform.lock.hcl")
    shutil.copytree(BOOTSTRAP / "tests", tmp_path / "tests")
    (tmp_path / "terraform.tfvars").write_text(
        'region = "eu-west-2"\n'
        'state_bucket_name = "bootstrap-backend-regression-does-not-exist"\n'
        'tags = { CostCenter = "test", Owner = "platform-security" }\n'
    )
    # Provider validation is disabled only in this isolated test directory.
    # The bucket has no prior state, so its targeted creation plan needs no API.
    (tmp_path / "provider_override.tf").write_text(
        'provider "aws" {\n'
        '  access_key = "testing"\n'
        '  secret_key = "testing"\n'
        "  skip_credentials_validation = true\n"
        "  skip_requesting_account_id = true\n"
        "  skip_metadata_api_check = true\n"
        "}\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith(("AWS_", "TF_"))}
    env["AWS_CONFIG_FILE"] = str(tmp_path / "absent-config")
    env["AWS_SHARED_CREDENTIALS_FILE"] = str(tmp_path / "absent-credentials")
    env["AWS_EC2_METADATA_DISABLED"] = "true"

    def run(*args: str) -> str:
        result = subprocess.run(
            [terraform, *args],
            cwd=tmp_path,
            env=env,
            text=True,
            capture_output=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        return result.stdout

    assert not (tmp_path / "terraform.tfstate").exists()
    run("init", "-input=false", "-no-color", f"-plugin-dir={plugins}")
    assert "Success!" in run("validate", "-no-color")
    run(
        "plan",
        "-input=false",
        "-no-color",
        "-refresh=false",
        "-target=aws_s3_bucket.state",
        "-var-file=terraform.tfvars",
        "-out=bootstrap.tfplan",
    )
    plan = json.loads(run("show", "-json", "bootstrap.tfplan"))
    assert [(item["address"], item["change"]["actions"]) for item in plan["resource_changes"]] == [
        ("aws_s3_bucket.state", ["create"])
    ]
    assert "1 passed, 0 failed" in run("test", "-no-color")
