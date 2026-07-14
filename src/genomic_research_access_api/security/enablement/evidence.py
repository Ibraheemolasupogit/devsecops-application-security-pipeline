"""Developer enablement evidence generation and verification."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from genomic_research_access_api.security.enablement.catalog import (
    AS_OF_DATE,
    COMMANDS,
    CONTROL_MAPPINGS,
    OUTPUT_DIR,
    PR_CHECKLIST_ITEMS,
    REPORT_DIR,
    REQUIRED_GUIDES,
    SCHEMA_VERSION,
    TIMESTAMP,
)
from genomic_research_access_api.security.findings.utils import read_json, relative, write_json
from genomic_research_access_api.security.threat_model.io import ROOT, sha256_file

MAKEFILE = ROOT / "Makefile"
OUTPUT_PATH = ROOT / OUTPUT_DIR
REPORT_PATH = ROOT / REPORT_DIR


def make_targets() -> set[str]:
    text = MAKEFILE.read_text(encoding="utf-8")
    targets: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith(("\t", "#", ".")) or ":" not in line:
            continue
        name = line.split(":", 1)[0].strip()
        if name and " " not in name and "=" not in name:
            targets.add(name)
    return targets


def command_inventory() -> dict[str, Any]:
    targets = make_targets()
    commands = []
    for item in COMMANDS:
        parts = item.command.split()
        target = parts[1] if len(parts) == 2 and parts[0] == "make" else ""
        commands.append(
            {
                "command": item.command,
                "category": item.category,
                "purpose": item.purpose,
                "prerequisites": item.prerequisites,
                "expected_output": item.expected_output,
                "modifies_tracked_evidence": item.modifies_tracked_evidence,
                "make_target_exists": not target or target in targets,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "command_count": len(commands),
        "commands": commands,
    }


def documentation_inventory() -> dict[str, Any]:
    guides = []
    for guide in REQUIRED_GUIDES:
        path = ROOT / guide.path
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        guides.append(
            {
                "path": guide.path,
                "title": guide.title,
                "purpose": guide.purpose,
                "exists": path.exists(),
                "word_count": len(text.split()),
                "sha256": sha256_file(path) if path.exists() else "",
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "guide_count": len(guides),
        "guides": guides,
    }


def prerequisite_summary() -> dict[str, Any]:
    docker_cli = shutil.which("docker")
    docker_daemon = _command_ok(["docker", "info"]) if docker_cli else False
    checks = [
        _tool(
            "python",
            shutil.which("python3") is not None,
            "available",
            "Required for all workflows.",
        ),
        _tool("git", shutil.which("git") is not None, "available", "Required for source control."),
        _tool(
            "docker_cli",
            docker_cli is not None,
            "unavailable",
            "Required for container-backed scanners.",
        ),
        _tool(
            "docker_daemon",
            docker_daemon,
            "unavailable",
            "Required for Trivy, ZAP and Docker fallback execution.",
        ),
        _tool(
            "terraform",
            shutil.which("terraform") is not None,
            "available",
            "Required for Terraform init/validate/test.",
        ),
        _tool(
            "gitleaks",
            shutil.which("gitleaks") is not None,
            "available_via_fallback" if docker_daemon else "unavailable",
            "Native binary optional; pinned Docker image is supported.",
        ),
        _tool(
            "trivy",
            shutil.which("trivy") is not None,
            "available_via_fallback" if docker_daemon else "unavailable",
            "Native binary optional; pinned Docker image is supported.",
        ),
        _tool(
            "aws_credentials", False, "not_required", "Milestone 11 does not deploy or access AWS."
        ),
    ]
    counts: dict[str, int] = {}
    for item in checks:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "checked_at": TIMESTAMP,
        "overall_status": "ready_with_fallbacks"
        if all(item["status"] != "unavailable" for item in checks)
        else "attention_required",
        "status_counts": counts,
        "checks": checks,
    }


def _tool(name: str, native_available: bool, fallback_status: str, notes: str) -> dict[str, Any]:
    return {
        "name": name,
        "status": "available" if native_available else fallback_status,
        "native_path": shutil.which(name.replace("_cli", "")) or "",
        "notes": notes,
    }


def _command_ok(command: list[str]) -> bool:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    return result.returncode == 0


def checklist_summary() -> dict[str, Any]:
    template = ROOT / ".github/pull_request_template.md"
    text = template.read_text(encoding="utf-8").lower() if template.exists() else ""
    items = [{"item": item, "covered": item.lower() in text} for item in PR_CHECKLIST_ITEMS]
    return {
        "schema_version": SCHEMA_VERSION,
        "checklist_item_count": len(items),
        "covered_count": sum(1 for item in items if item["covered"]),
        "items": items,
    }


def control_mapping() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "mapping_count": len(CONTROL_MAPPINGS),
        "mappings": CONTROL_MAPPINGS,
    }


def enablement_summary() -> dict[str, Any]:
    docs = documentation_inventory()
    commands = command_inventory()
    prereqs = prerequisite_summary()
    checklist = checklist_summary()
    mapping = control_mapping()
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": TIMESTAMP,
        "as_of_date": AS_OF_DATE,
        "guide_count": docs["guide_count"],
        "command_count": commands["command_count"],
        "developer_control_mapping_count": mapping["mapping_count"],
        "pull_request_checklist_coverage": {
            "covered": checklist["covered_count"],
            "total": checklist["checklist_item_count"],
        },
        "prerequisite_status_counts": prereqs["status_counts"],
        "local_only": True,
        "deployment_status": "not_deployed",
        "milestone_boundary": (
            "Milestone 11 only; Milestone 12 Security Champions is not implemented."
        ),
    }


def generate(output_dir: Path = OUTPUT_PATH) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    outputs = {
        "command-inventory.json": command_inventory(),
        "documentation-inventory.json": documentation_inventory(),
        "developer-control-mapping.json": control_mapping(),
        "prerequisite-check-summary.json": prerequisite_summary(),
        "pull-request-checklist-summary.json": checklist_summary(),
        "enablement-summary.json": enablement_summary(),
    }
    written = []
    for name, payload in outputs.items():
        path = output_dir / name
        write_json(path, payload)
        written.append(path)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "controlled_timestamp": TIMESTAMP,
        "as_of_date": AS_OF_DATE,
        "repository": "devsecops-application-security-pipeline",
        "deployment_status": "not_deployed",
        "output_files": {
            path.name: {"path": path.name, "sha256": sha256_file(path)} for path in sorted(written)
        },
    }
    manifest_path = output_dir / "evidence-manifest.json"
    write_json(manifest_path, manifest)
    written.append(manifest_path)
    return written


def verify(output_dir: Path = OUTPUT_PATH) -> None:
    manifest_path = output_dir / "evidence-manifest.json"
    if not manifest_path.exists():
        raise ValueError("developer enablement evidence manifest missing")
    manifest = read_json(manifest_path)
    errors = []
    for name, details in manifest["output_files"].items():
        path = output_dir / str(details["path"])
        if not path.exists():
            errors.append(f"missing output: {name}")
        elif sha256_file(path) != details["sha256"]:
            errors.append(f"checksum mismatch: {name}")
    docs = read_json(output_dir / "documentation-inventory.json")
    if any(not guide["exists"] or guide["word_count"] < 120 for guide in docs["guides"]):
        errors.append("documentation inventory contains missing or thin guides")
    commands = read_json(output_dir / "command-inventory.json")
    if any(not command["make_target_exists"] for command in commands["commands"]):
        errors.append("command inventory references missing Make targets")
    checklist = read_json(output_dir / "pull-request-checklist-summary.json")
    if checklist["covered_count"] != checklist["checklist_item_count"]:
        errors.append("pull request checklist is incomplete")
    if errors:
        raise ValueError("\n".join(sorted(errors)))


MAKE_PATTERN = re.compile(r"`(make [a-zA-Z0-9_.:-]+(?: [a-zA-Z0-9_.:-]+)*)`")
PATH_PATTERN = re.compile(
    r"`((?:docs|scripts|outputs|reports|config|security|infrastructure|tests|src)/[^`]+)`"
)
MD_LINK_PATTERN = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
THREAT_PATTERN = re.compile(r"\bTHR-[A-Z]+-[0-9]{3}\b")
REQ_PATTERN = re.compile(r"\bSR-[A-Z]+-[0-9]{3}\b")
SECRET_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}"
)


def validate_docs() -> dict[str, Any]:
    targets = make_targets()
    requirements = {
        item["requirement_id"]
        for item in read_json(ROOT / "docs/threat-model/security-requirements.yaml")
    }
    threats = {
        item["threat_id"] for item in read_json(ROOT / "docs/threat-model/threat-register.yaml")
    }
    errors: list[str] = []
    for guide in REQUIRED_GUIDES:
        path = ROOT / guide.path
        if not path.exists():
            errors.append(f"missing guide: {guide.path}")
            continue
        text = path.read_text(encoding="utf-8")
        if len(text.split()) < 120:
            errors.append(f"guide is not substantive: {guide.path}")
        if "/Users/" in text or "/private/" in text:
            errors.append(f"absolute local path found: {guide.path}")
        if SECRET_PATTERN.search(text):
            errors.append(f"secret-like content found: {guide.path}")
        if "permanent exception" in text.lower():
            errors.append(f"permanent exception language found: {guide.path}")
        for match in MAKE_PATTERN.findall(text):
            for target in match.split()[1:]:
                if target not in targets:
                    errors.append(f"missing Make target {target} in {guide.path}")
        for path_ref in PATH_PATTERN.findall(text):
            clean = path_ref.rstrip(".,;:")
            if not (ROOT / clean).exists():
                errors.append(f"missing referenced path {clean} in {guide.path}")
        for link in MD_LINK_PATTERN.findall(text):
            if link.startswith(("http://", "https://", "#", "mailto:")):
                continue
            link_path = link.split("#", 1)[0]
            if link_path and not (path.parent / link_path).resolve().exists():
                errors.append(f"broken markdown link {link} in {guide.path}")
        for threat in THREAT_PATTERN.findall(text):
            if threat not in threats:
                errors.append(f"unknown threat {threat} in {guide.path}")
        for requirement in REQ_PATTERN.findall(text):
            if requirement not in requirements:
                errors.append(f"unknown requirement {requirement} in {guide.path}")
    result = {"schema_version": SCHEMA_VERSION, "valid": not errors, "errors": sorted(set(errors))}
    if errors:
        raise ValueError(json.dumps(result, indent=2, sort_keys=True))
    return result


def report() -> list[Path]:
    REPORT_PATH.mkdir(parents=True, exist_ok=True)
    summary = read_json(OUTPUT_PATH / "enablement-summary.json")
    prereqs = read_json(OUTPUT_PATH / "prerequisite-check-summary.json")
    checklist = read_json(OUTPUT_PATH / "pull-request-checklist-summary.json")
    mapping = read_json(OUTPUT_PATH / "developer-control-mapping.json")
    reports = {
        "developer-enablement-report.md": _render_enablement(summary, mapping),
        "developer-onboarding-report.md": _render_onboarding(summary, prereqs),
        "developer-security-workflow-report.md": _render_workflow(summary),
        "pull-request-security-report.md": _render_pr(checklist),
        "security-tooling-readiness-report.md": _render_readiness(prereqs),
    }
    written = []
    for name, text in reports.items():
        path = REPORT_PATH / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written


def _render_enablement(summary: dict[str, Any], mapping: dict[str, Any]) -> str:
    return (
        "# Developer Enablement Report\n\n"
        f"- Guides: {summary['guide_count']}\n"
        f"- Commands: {summary['command_count']}\n"
        f"- Developer-control mappings: {mapping['mapping_count']}\n"
        "- Deployment status: not_deployed\n"
        "- Milestone boundary: Milestone 11 only; Security Champions remains future work.\n"
    )


def _render_onboarding(summary: dict[str, Any], prereqs: dict[str, Any]) -> str:
    return (
        "# Developer Onboarding Report\n\n"
        f"The onboarding path covers {summary['guide_count']} guides and "
        f"{summary['command_count']} commands.\n\n"
        f"Prerequisite status: {prereqs['overall_status']}.\n"
    )


def _render_workflow(summary: dict[str, Any]) -> str:
    return (
        "# Developer Security Workflow Report\n\n"
        "The workflow links planning, local checks, pull request review, scanner triage, "
        "release assurance, lifecycle governance and consolidated evidence.\n\n"
        f"Checklist coverage: {summary['pull_request_checklist_coverage']['covered']}/"
        f"{summary['pull_request_checklist_coverage']['total']}.\n"
    )


def _render_pr(checklist: dict[str, Any]) -> str:
    lines = ["# Pull Request Security Report", ""]
    for item in checklist["items"]:
        marker = "covered" if item["covered"] else "missing"
        lines.append(f"- {item['item']}: {marker}")
    return "\n".join(lines) + "\n"


def _render_readiness(prereqs: dict[str, Any]) -> str:
    lines = [
        "# Security Tooling Readiness Report",
        "",
        f"Overall status: {prereqs['overall_status']}.",
        "",
    ]
    for item in prereqs["checks"]:
        lines.append(f"- {item['name']}: {item['status']} - {item['notes']}")
    return "\n".join(lines) + "\n"


def doctor() -> dict[str, Any]:
    OUTPUT_PATH.mkdir(parents=True, exist_ok=True)
    summary = prerequisite_summary()
    write_json(OUTPUT_PATH / "prerequisite-check-summary.json", summary)
    return summary


def path_summary(paths: list[Path]) -> list[str]:
    return [relative(path) for path in paths]
