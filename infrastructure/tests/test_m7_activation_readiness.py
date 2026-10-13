"""M7 preparation must remain offline/read-only until separately approved."""

from __future__ import annotations

from pathlib import Path

from genomic_research_access_api.security.supply_chain.contract import evaluate_publication

ROOT = Path(__file__).resolve().parents[2]
TF = ROOT / "infrastructure/terraform"


def test_make_and_workflows_have_no_apply_or_destroy_execution_path() -> None:
    makefile = (ROOT / "Makefile").read_text()
    assert "terraform-bootstrap-validate:" in makefile
    assert "nonprod-plan:" in makefile
    assert "terraform apply" not in makefile
    assert "terraform destroy" not in makefile
    assert "terraform apply" not in "\n".join(
        workflow.read_text() for workflow in (ROOT / ".github/workflows").glob("*.yml")
    )


def test_m7_plan_target_excludes_production_and_bootstrap_apply() -> None:
    makefile = (ROOT / "Makefile").read_text()
    target = makefile.split("nonprod-plan:", 1)[1].split("\n\n", 1)[0]
    assert "environments/nonprod" in target
    assert "environments/prod" not in target
    assert "plan" in target and "apply" not in target
    assert "terraform -chdir=infrastructure/terraform/bootstrap init -backend=false" in makefile


def test_bootstrap_state_has_encryption_versioning_locking_and_recovery_guards() -> None:
    bootstrap = "\n".join(path.read_text() for path in (TF / "bootstrap").glob("*.tf"))
    assert 'sse_algorithm     = "aws:kms"' in bootstrap
    assert 'status = "Enabled"' in bootstrap
    assert "prevent_destroy = true" in bootstrap
    assert "force_destroy = false" in bootstrap
    assert "block_public_acls       = true" in bootstrap
    assert "aws:SecureTransport" in bootstrap
    assert "enable_key_rotation     = true" in bootstrap
    assert 'id     = "abort-incomplete-uploads"' in bootstrap
    assert "days_after_initiation = 7" in bootstrap
    assert '"bootstrap/terraform.tfstate"' in (TF / "bootstrap/backend.hcl.example").read_text()
    for environment in ("nonprod", "prod", "artifacts"):
        backend = (
            TF
            / ("artifacts" if environment == "artifacts" else f"environments/{environment}")
            / "backend.hcl.example"
        ).read_text()
        assert f'key = "eks/{environment}/terraform.tfstate"' in backend
        assert "encrypt = true" in backend
        assert "kms_key_id" in backend
        assert "use_lockfile = true" in backend


def test_role_contracts_are_separate_and_static_credentials_absent() -> None:
    role_module = (TF / "modules/github-actions-role/main.tf").read_text()
    platform = (TF / "modules/platform/main.tf").read_text()
    artifact = (TF / "artifacts/main.tf").read_text()
    assert 'role_kind         = "publisher"' in artifact
    assert 'role_kind         = "deployer"' in platform
    assert 'module "deployment_identity"' in platform
    assert "eks:DescribeCluster" in role_module
    assert "ecr:PutImage" in role_module
    assert "aws_access_key_id" not in "\n".join(p.read_text().lower() for p in TF.rglob("*.tf"))
    assert "aws_secret_access_key" not in "\n".join(p.read_text().lower() for p in TF.rglob("*.tf"))


def test_clean_candidate_and_eligible_decision_are_mandatory_for_publication() -> None:
    decision = evaluate_publication(
        build_succeeded=True,
        build_integrity=True,
        image_digest="sha256:" + "a" * 64,
        sbom_integrity=True,
        scan_completed=True,
        scan_blocking_count=0,
        provenance_integrity=True,
        release_decision="pass",
        worktree_clean=False,
    )
    assert decision["status"] == "blocked"
    assert decision["publication_allowed"] is False
    assert any("worktree is dirty" in blocker for blocker in decision["blockers"])
    conditional = evaluate_publication(
        build_succeeded=True,
        build_integrity=True,
        image_digest="sha256:" + "a" * 64,
        sbom_integrity=True,
        scan_completed=True,
        scan_blocking_count=0,
        provenance_integrity=True,
        release_decision="conditional_pass",
        worktree_clean=True,
    )
    assert conditional["status"] == "conditionally_eligible"
    assert conditional["publication_allowed"] is False


def test_current_supply_chain_contract_forbids_latest_and_unpublished_promotion() -> None:
    source = (ROOT / "tests/security/test_supply_chain.py").read_text()
    assert "test_github_sha_tag_is_metadata_not_promotion_identity" in source
    assert "test_missing_or_mismatched_published_digest_cannot_be_verified" in source
    assert '"published_digest": None' in source
    assert "test_dirty_source_worktree_blocks_publication" in source
    workflow = (ROOT / ".github/workflows/build-publish.yml").read_text()
    assert "publication_mode" in workflow
    assert "terraform apply" not in workflow


def test_stage_a_does_not_run_implicitly() -> None:
    docs = (ROOT / "docs/runbooks/nonprod-platform-activation.md").read_text()
    assert "No Stage A apply or migration has run" in docs
    assert "A separate explicit approval is required" in docs
    assert "terraform apply bootstrap.tfplan" in docs  # documented, never a target


def test_readiness_script_uses_no_mutating_aws_operations() -> None:
    source = (ROOT / "scripts/aws_readiness.py").read_text()
    assert '"sts", "get-caller-identity"' in source
    assert '"configure", "get", "region"' in source
    for operation in ("create-", "delete-", "update-", "put-", "attach-", "authorize-"):
        assert operation not in source


def test_nonprod_teardown_order_preserves_state_artifacts_and_keys() -> None:
    runbook = (ROOT / "docs/runbooks/nonprod-platform-activation.md").read_text()
    expected_order = (
        "remove QA Kustomize resources first",
        "remove the runner project",
        "Remove the EKS managed node group",
        "remove VPC endpoints, NAT gateway/EIP",
        "do not delete KMS keys",
        "Keep the separate shared ECR artifact stack",
        "Keep the bootstrap S3 bucket",
    )
    positions = [runbook.index(value) for value in expected_order]
    assert positions == sorted(positions)
    assert "no destroy plan was generated and no destroy was run" in runbook
