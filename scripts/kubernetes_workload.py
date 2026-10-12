"""Render, validate and scan the offline Kustomize workload overlays."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).resolve().parents[1]
OVERLAYS = ("qa", "prod")
PLATFORM_ROOTS = ("nonprod", "prod")
RBAC_ROOTS = ("qa", "prod")


def render(environment: str) -> str:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise RuntimeError("kubectl with Kustomize support is required; no cluster is contacted")
    result = subprocess.run(
        [kubectl, "kustomize", str(ROOT / "kubernetes" / "overlays" / environment)],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return result.stdout


def render_root(category: str, name: str) -> str:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        raise RuntimeError("kubectl with Kustomize support is required; no cluster is contacted")
    result = subprocess.run(
        [kubectl, "kustomize", str(ROOT / "kubernetes" / category / name)],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return result.stdout


def documents(rendered: str) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for value in yaml.safe_load_all(rendered):
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError("Kustomize output must contain Kubernetes object mappings")
        result.append(value)
    return result


def validate() -> None:
    roots = [("overlays", name) for name in OVERLAYS]
    roots += [("platform", name) for name in PLATFORM_ROOTS]
    roots += [("rbac", name) for name in RBAC_ROOTS]
    for category, environment in roots:
        rendered = (
            render(environment) if category == "overlays" else render_root(category, environment)
        )
        objects = documents(rendered)
        if not objects:
            raise ValueError(f"{environment} rendered no Kubernetes resources")
        seen: set[tuple[object, object, object]] = set()
        for resource in objects:
            for field in ("apiVersion", "kind", "metadata"):
                if field not in resource:
                    raise ValueError(f"{environment} resource is missing {field}")
            metadata = resource["metadata"]
            if not isinstance(metadata, dict) or not metadata.get("name"):
                raise ValueError(f"{environment} resource is missing metadata.name")
            key = (resource["apiVersion"], resource["kind"], metadata["name"])
            if key in seen:
                raise ValueError(f"{environment} contains duplicate object identity: {key}")
            seen.add(key)
            if resource["kind"] == "Secret":
                raise ValueError("Kustomize manifests must reference externally managed Secrets")
        if "-----BEGIN PRIVATE KEY-----" in rendered or "AKIA" in rendered:
            raise ValueError("rendered workload contains a credential-like value")
        print(f"{category}/{environment}: valid YAML; {len(objects)} unique Kubernetes resources")


def render_command() -> None:
    for environment in OVERLAYS:
        print(f"# {environment} overlay")
        print(render(environment), end="")
    for category, environments in (("platform", PLATFORM_ROOTS), ("rbac", RBAC_ROOTS)):
        for environment in environments:
            print(f"# {category}/{environment} bootstrap contract")
            print(render_root(category, environment), end="")


def security() -> None:
    checkov = shutil.which("checkov")
    if checkov is None:
        candidate = ROOT / ".venv" / "bin" / "checkov"
        checkov = str(candidate) if candidate.is_file() else None
    if checkov is None:
        raise RuntimeError("Checkov is required for the Kubernetes policy scan")
    with tempfile.TemporaryDirectory(prefix="k8s-rendered-") as temporary:
        directory = Path(temporary)
        for environment in OVERLAYS:
            target = directory / f"workload-{environment}.yaml"
            target.write_text(render(environment), encoding="utf-8")
        for category, environments in (("platform", PLATFORM_ROOTS), ("rbac", RBAC_ROOTS)):
            for environment in environments:
                target = directory / f"{category}-{environment}.yaml"
                target.write_text(render_root(category, environment), encoding="utf-8")
        subprocess.run(
            [checkov, "--framework", "kubernetes", "--directory", str(directory)],
            check=True,
            cwd=ROOT,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("render", "validate", "security"))
    command = parser.parse_args().command
    try:
        {"render": render_command, "validate": validate, "security": security}[command]()
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Kubernetes workload {command} failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
