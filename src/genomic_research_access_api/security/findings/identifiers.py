"""Deterministic finding identifiers and source hashes."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from genomic_research_access_api.security.threat_model.io import ROOT


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_hash(payload: Any, length: int = 12) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:length]


def source_record_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def finding_id(domain: str, key: Any) -> str:
    domain_token = "".join(ch for ch in domain.upper() if ch.isalnum())[:10] or "SEC"
    return f"FND-{domain_token}-{stable_hash(key)}"


def normalise_path(path: str | None) -> str | None:
    if not path:
        return None
    value = path.replace("\\", "/")
    root = str(ROOT).replace("\\", "/")
    if value.startswith(root + "/"):
        value = value[len(root) + 1 :]
    if value.startswith("./"):
        value = value[2:]
    parts = [part for part in value.split("/") if part not in {"", "."}]
    clean: list[str] = []
    for part in parts:
        if part == "..":
            if clean:
                clean.pop()
        else:
            clean.append(part)
    return "/".join(clean)
