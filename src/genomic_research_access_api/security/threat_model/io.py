"""Input and output helpers for deterministic threat-model artefacts."""

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
THREAT_MODEL_DIR = ROOT / "docs" / "threat-model"
OUTPUT_DIR = ROOT / "outputs" / "security" / "threat-model"
REPORT_DIR = ROOT / "reports" / "security"


SOURCE_FILES = {
    "assets": THREAT_MODEL_DIR / "assets.yaml",
    "actors": THREAT_MODEL_DIR / "actors.yaml",
    "entry_points": THREAT_MODEL_DIR / "entry-points.yaml",
    "trust_boundaries": THREAT_MODEL_DIR / "trust-boundaries.yaml",
    "data_flows": THREAT_MODEL_DIR / "data-flows.yaml",
    "threats": THREAT_MODEL_DIR / "threat-register.yaml",
    "requirements": THREAT_MODEL_DIR / "security-requirements.yaml",
    "traceability": THREAT_MODEL_DIR / "control-traceability.yaml",
    "residual_risks": THREAT_MODEL_DIR / "residual-risk-register.yaml",
}


def load_json_yaml(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalise_model(model: Any) -> Any:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    if isinstance(model, list):
        return [normalise_model(item) for item in model]
    return model
