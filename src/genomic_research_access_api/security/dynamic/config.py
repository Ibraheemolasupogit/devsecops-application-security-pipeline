"""Configuration paths for dynamic security evidence."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[4]
CONFIG_PATH = ROOT / "security/dynamic/config.yaml"
POLICY_PATH = ROOT / "security/dynamic/policy.yaml"
OUTPUT_DIR = ROOT / "outputs/security/dynamic"
RAW_DIR = OUTPUT_DIR / "raw"
REPORT_DIR = ROOT / "reports/security"
MANIFEST_PATH = OUTPUT_DIR / "evidence-manifest.json"


def load_json_yaml(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def dynamic_config() -> dict[str, Any]:
    return load_json_yaml(CONFIG_PATH)


def dynamic_policy() -> dict[str, Any]:
    return cast(dict[str, Any], load_json_yaml(POLICY_PATH)["policy"])


def validate_local_target(url: str) -> str:
    config = dynamic_config()
    parsed = urlparse(url)
    allowed_hosts = set(config["local_targets"]["allowed_hosts"])
    if parsed.scheme not in config["local_targets"]["allowed_schemes"]:
        raise ValueError(f"Dynamic scan target scheme is not allowed: {parsed.scheme}")
    host = parsed.hostname or ""
    if host not in allowed_hosts:
        raise ValueError(f"Dynamic scan target host is not allowed: {host}")
    if host not in {"host.docker.internal", "api"}:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 80)}
        if not addresses.issubset({"127.0.0.1", "::1"}):
            raise ValueError(f"Dynamic scan target resolved outside localhost: {host}")
    return url
