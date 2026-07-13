"""Typed models for consolidated evidence."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"


class SourceDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_id: str
    domain: str
    name: str
    manifest_path: str
    required: bool
    expected_schema_version: str
    expected_outputs: list[str]
    verification_command: str
    owner: str
    retention_class: str
    contains_sensitive_data: bool
    deployment_status: str


class DomainEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_id: str
    name: str
    source_manifest: str
    schema_version: str
    expected_outputs: list[str]
    required: bool
    verification_status: str
    source_checksum: str
    generated_at: str
    evidence_timestamp: str
    deployment_status: str
    limitations: list[str] = Field(default_factory=list)
    missing_outputs: list[str] = Field(default_factory=list)
    checksum_failures: list[str] = Field(default_factory=list)


class ConsolidatedEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str
    evidence_bundle_id: str
    project_name: str
    project_version: str
    repository: str
    branch: str
    commit: str
    dirty_worktree: bool
    controlled_timestamp: str
    as_of_date: str
    deployment_status: str
    domain_count: int
    verified_domain_count: int
    failed_domain_count: int
    required_domain_count: int
    domains: list[DomainEvidence]
    input_manifests: dict[str, str]
    input_checksums: dict[str, str]
    control_coverage: dict[str, Any]
    metrics: dict[str, Any]
    release_decision: dict[str, Any]
    finding_summary: dict[str, Any]
    lifecycle_summary: dict[str, Any]
    exception_summary: dict[str, Any]
    verification_summary: dict[str, Any]
    limitations: list[str]
    output_checksums: dict[str, str] = Field(default_factory=dict)
