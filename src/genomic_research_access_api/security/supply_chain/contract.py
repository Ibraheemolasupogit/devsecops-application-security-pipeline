"""Pure contract functions shared by the supply-chain CLI and tests."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any


class SupplyChainError(ValueError):
    """Raised when artifact identity or assurance evidence is invalid."""


_DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
_ECR_HOST = re.compile(r"^[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$")


def canonical_json(payload: Any) -> str:
    """Serialize stable JSON with no machine-specific formatting."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_digest(value: object) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise SupplyChainError("artifact identity must be a sha256 OCI digest")
    return value


def validate_release_reference(repository: str, region: str) -> tuple[str, str]:
    host, separator, name = repository.partition("/")
    if not separator or not _ECR_HOST.fullmatch(host):
        raise SupplyChainError(
            "ECR repository URL must contain an AWS account and regional ECR host"
        )
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/-]*", name) or ".." in name:
        raise SupplyChainError("ECR repository name is invalid")
    repository_region = host.split(".")[3]
    if region != repository_region:
        raise SupplyChainError("AWS region does not match the ECR repository URL")
    return host, name


def evaluate_publication(
    *,
    build_succeeded: bool,
    build_integrity: bool,
    image_digest: object,
    sbom_integrity: bool,
    scan_completed: bool,
    scan_blocking_count: int | None,
    provenance_integrity: bool,
    release_decision: str | None,
    worktree_clean: bool = True,
) -> dict[str, Any]:
    """Map existing release assurance plus artifact checks to publication state."""
    blockers: list[str] = []
    conditions: list[str] = []
    if not build_succeeded:
        blockers.append("container build did not complete")
    if not build_integrity:
        blockers.append("build metadata integrity was not established")
    if not worktree_clean:
        blockers.append("source worktree is dirty; candidate is not attributable to its commit")
    try:
        validate_digest(image_digest)
    except SupplyChainError:
        blockers.append("built artifact digest is missing or invalid")
    if not sbom_integrity:
        blockers.append("container SBOM integrity was not established")
    if not scan_completed or scan_blocking_count is None:
        blockers.append("container vulnerability scan did not complete")
    elif scan_blocking_count > 0:
        blockers.append("container scan contains policy-blocking findings")
    if not provenance_integrity:
        blockers.append("provenance chain integrity was not established")
    if release_decision is None:
        blockers.append("canonical release decision is missing")
    elif release_decision == "block":
        blockers.append("canonical release policy blocked publication")
    elif release_decision == "conditional_pass":
        conditions.append("canonical release policy requires its recorded approvals")
    elif release_decision != "pass":
        blockers.append("canonical release decision is not a recognised pass state")

    status = "blocked" if blockers else "conditionally_eligible" if conditions else "eligible"
    return {
        "schema_version": "1.0",
        "status": status,
        "publication_allowed": status == "eligible",
        "blockers": sorted(blockers),
        "conditions": sorted(conditions),
        "release_decision": release_decision or "not_available",
        "artifact_digest": image_digest if isinstance(image_digest, str) else None,
    }


def validate_publication_manifest(manifest: Mapping[str, Any]) -> None:
    validate_digest(manifest.get("local_digest"))
    published = manifest.get("published_digest")
    if published is not None:
        validate_digest(published)
        if published != manifest["local_digest"]:
            raise SupplyChainError("published digest does not match the locally assured artifact")
    if published is None and manifest.get("verification_status") == "published_verified":
        raise SupplyChainError("verified publication cannot omit its ECR digest")
    if manifest.get("source_image_tag") == "latest" or str(
        manifest.get("source_image_tag", "")
    ).endswith(":latest"):
        raise SupplyChainError("latest is not an artifact identity")
    if manifest.get("publication_decision") == "blocked" and published is not None:
        raise SupplyChainError("blocked artifacts cannot claim a published digest")


def validate_checksum_index(
    expected: Mapping[str, str], checksum_text: str, manifest_files: Mapping[str, Any]
) -> None:
    expected_text = "".join(f"{digest}  {name}\n" for name, digest in sorted(expected.items()))
    if checksum_text != expected_text:
        raise SupplyChainError("supply-chain file checksum verification failed")
    if set(manifest_files) != set(expected):
        raise SupplyChainError(
            "supply-chain manifest file set differs from the expected evidence set"
        )
    for name, digest in expected.items():
        details = manifest_files[name]
        if not isinstance(details, Mapping) or details.get("sha256") != digest:
            raise SupplyChainError(f"supply-chain manifest checksum mismatch: {name}")
