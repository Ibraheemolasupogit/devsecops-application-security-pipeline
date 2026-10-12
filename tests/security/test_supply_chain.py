from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]

from genomic_research_access_api.security.supply_chain.contract import (
    SupplyChainError,
    canonical_json,
    evaluate_publication,
    validate_checksum_index,
    validate_digest,
    validate_publication_manifest,
    validate_release_reference,
)
from genomic_research_access_api.security.supply_chain.runner import (
    _source_identity,
    validate_assurance_links,
)
from genomic_research_access_api.security.threat_model.io import ROOT

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
COMMIT = "1" * 40


def _eligibility(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "build_succeeded": True,
        "build_integrity": True,
        "image_digest": DIGEST,
        "sbom_integrity": True,
        "scan_completed": True,
        "scan_blocking_count": 0,
        "provenance_integrity": True,
        "release_decision": "pass",
    }
    values.update(overrides)
    return evaluate_publication(**values)


def test_digest_is_the_authoritative_release_identity() -> None:
    assert validate_digest(DIGEST) == DIGEST
    assert _eligibility()["status"] == "eligible"


@pytest.mark.parametrize("value", [None, "", "latest", "sha256:abc", "sha512:" + "a" * 128])
def test_invalid_or_missing_artifact_digest_is_rejected(value: object) -> None:
    with pytest.raises(SupplyChainError):
        validate_digest(value)
    assert _eligibility(image_digest=value)["status"] == "blocked"


def test_github_sha_tag_is_metadata_not_promotion_identity() -> None:
    manifest = {
        "local_digest": DIGEST,
        "published_digest": None,
        "source_image_tag": f"genomic-research-access-api:git-{COMMIT}",
        "publication_decision": "eligible",
        "verification_status": "locally_verified",
    }
    assert manifest["published_digest"] is None
    assert manifest["verification_status"] == "locally_verified"
    validate_publication_manifest(manifest)
    manifest["source_image_tag"] = "genomic-research-access-api:latest"
    with pytest.raises(SupplyChainError, match="latest"):
        validate_publication_manifest(manifest)


def test_missing_or_mismatched_published_digest_cannot_be_verified() -> None:
    manifest = {
        "local_digest": DIGEST,
        "published_digest": None,
        "source_image_tag": f"genomic-research-access-api:git-{COMMIT}",
        "publication_decision": "eligible",
        "verification_status": "published_verified",
    }
    with pytest.raises(SupplyChainError, match="omit its ECR digest"):
        validate_publication_manifest(manifest)
    manifest["published_digest"] = OTHER_DIGEST
    with pytest.raises(SupplyChainError, match="does not match"):
        validate_publication_manifest(manifest)


def test_blocking_scan_and_release_policy_block_publication() -> None:
    assert _eligibility(scan_blocking_count=1)["status"] == "blocked"
    assert _eligibility(release_decision="block")["status"] == "blocked"
    assert _eligibility(scan_completed=False)["status"] == "blocked"
    assert _eligibility(provenance_integrity=False)["status"] == "blocked"


def test_dirty_source_worktree_blocks_publication() -> None:
    clean_result = _eligibility(worktree_clean=True)
    result = _eligibility(worktree_clean=False)
    assert clean_result["status"] == "eligible"
    assert clean_result["publication_allowed"] is True
    assert result["status"] == "blocked"
    assert any("worktree is dirty" in blocker for blocker in result["blockers"])


def test_conditional_release_result_remains_conditional() -> None:
    result = _eligibility(release_decision="conditional_pass")
    assert result["status"] == "conditionally_eligible"
    assert result["publication_allowed"] is False
    assert result["conditions"]


def test_sbom_scan_provenance_and_release_artifact_must_share_digest() -> None:
    artifact = {"local_digest": DIGEST, "published_digest": None}
    sbom = {"artifact_digest": DIGEST}
    scan = {"image_digest": DIGEST}
    provenance = {"image_digest": DIGEST}
    validate_assurance_links(artifact, sbom, scan, provenance)
    scan["image_digest"] = OTHER_DIGEST
    with pytest.raises(SupplyChainError, match="do not match"):
        validate_assurance_links(artifact, sbom, scan, provenance)


def test_canonical_json_is_stable_and_sorted() -> None:
    assert canonical_json({"z": 1, "a": 2}) == '{"a":2,"z":1}\n'
    assert canonical_json({"a": 2, "z": 1}) == canonical_json({"z": 1, "a": 2})


def test_checksum_index_rejects_tampered_or_missing_evidence() -> None:
    expected = {"build-metadata.json": "c" * 64, "provenance.json": "d" * 64}
    index = "".join(f"{value}  {name}\n" for name, value in sorted(expected.items()))
    files = {name: {"sha256": value} for name, value in expected.items()}
    validate_checksum_index(expected, index, files)
    with pytest.raises(SupplyChainError, match="checksum"):
        validate_checksum_index(expected, index.replace("c" * 64, "e" * 64), files)
    with pytest.raises(SupplyChainError, match="file set"):
        validate_checksum_index(
            expected, index, {"build-metadata.json": files["build-metadata.json"]}
        )


def test_source_identity_records_dirty_source_tree_but_ignores_generated_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        [COMMIT, "1791806400", " M src/example.py\n?? outputs/security/supply-chain/x.json"]
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.supply_chain.runner._git", lambda *_: next(responses)
    )
    commit, timestamp, dirty = _source_identity()
    assert commit == COMMIT
    assert timestamp.endswith("Z")
    assert dirty is True


def test_source_identity_is_clean_for_generated_evidence_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        [COMMIT, "1791806400", " M outputs/security/findings/x.json\n?? reports/security/x.md"]
    )
    monkeypatch.setattr(
        "genomic_research_access_api.security.supply_chain.runner._git", lambda *_: next(responses)
    )
    assert _source_identity()[2] is False


def test_ecr_repository_and_region_are_exact() -> None:
    host, name = validate_release_reference(
        "123456789012.dkr.ecr.eu-west-2.amazonaws.com/genomic-research-access-api",
        "eu-west-2",
    )
    assert host == "123456789012.dkr.ecr.eu-west-2.amazonaws.com"
    assert name == "genomic-research-access-api"
    with pytest.raises(SupplyChainError, match="region"):
        validate_release_reference(
            "123456789012.dkr.ecr.eu-west-2.amazonaws.com/genomic-research-access-api",
            "eu-west-1",
        )
    with pytest.raises(SupplyChainError):
        validate_release_reference("docker.io/example/api", "eu-west-2")


def test_dockerfile_preserves_kubernetes_runtime_security_and_labels() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert (
        dockerfile.count(
            "python:3.11.17-slim-trixie@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce"
        )
        == 2
    )
    assert " AS builder" in dockerfile and " AS runtime" in dockerfile
    assert "--gid 10001" in dockerfile and "--uid 10001" in dockerfile
    assert "USER appuser" in dockerfile
    assert "org.opencontainers.image.revision" in dockerfile
    assert "org.opencontainers.image.version" in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert "apt-get -y upgrade" not in dockerfile
    assert 'ENTRYPOINT ["sh"' not in dockerfile


def test_workflow_has_read_only_content_and_pinned_oidc_publication_action() -> None:
    path = ROOT / ".github/workflows/build-publish.yml"
    raw = path.read_text(encoding="utf-8")
    workflow = yaml.safe_load(raw)
    event_rules = workflow.get("on", workflow.get(True))
    assert "pull_request" in event_rules and "workflow_dispatch" in event_rules
    assert workflow["permissions"] == {"contents": "read", "id-token": "write"}
    assert "secrets.AWS_ACCESS_KEY_ID" not in raw
    assert "AWS_SECRET_ACCESS_KEY:" not in raw
    assert "latest" not in raw
    action_refs = re.findall(r"uses:\s*[^\s@]+@([a-f0-9]+)", raw)
    assert action_refs and all(len(ref) == 40 for ref in action_refs)
    assert "aws-actions/configure-aws-credentials@" in raw
    assert "publication_mode" in raw and "verify" in raw
    assert "retention-days: 14" in raw
    assert "SUPPLY_CHAIN_ALLOW_LIVE_PUBLICATION" in raw


def test_ci_does_not_rebuild_image_outside_canonical_pipeline() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    container = (ROOT / ".github/workflows/build-publish.yml").read_text(encoding="utf-8")
    assert "docker build" not in ci
    assert "make supply-chain-full" in container
    assert "docker buildx build" not in container


def test_supply_chain_schemas_are_valid_json_schemas() -> None:
    for path in sorted((ROOT / "schemas/security/supply-chain").glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema, format_checker=FormatChecker())


def test_metadata_json_contains_no_machine_paths_or_secret_fields(tmp_path: Path) -> None:
    from genomic_research_access_api.security.supply_chain.runner import _write_json

    path = tmp_path / "build-metadata.json"
    _write_json(
        path,
        {
            "source_commit": COMMIT,
            "image_digest": DIGEST,
            "dockerfile_sha256": "e" * 64,
            "dependency_definition_sha256": "f" * 64,
            "dirty_worktree": True,
        },
    )
    text = path.read_text(encoding="utf-8")
    assert "/Users/" not in text and "/private/" not in text
    assert not re.search(r"AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)|password|private_key", text, re.I)


def test_runtime_validation_uses_nonroot_readonly_image_contract() -> None:
    source = (ROOT / "src/genomic_research_access_api/security/supply_chain/runner.py").read_text(
        encoding="utf-8"
    )
    for control in (
        '"--read-only"',
        'runtime_tmp = os.path.join(os.sep, "tmp")',
        'f"{runtime_tmp}:rw,noexec,nosuid,size=16m"',
        '"--user"',
        '"10001:10001"',
        '"--network"',
        '"none"',
        "http://127.0.0.1:8000/health",
    ):
        assert control in source
