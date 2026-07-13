"""Parsers for Milestone 6 dynamic security raw outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

TEST_CATEGORY_BY_NAME = {
    "test_authentication_boundary_failures": "authentication",
    "test_authorisation_role_matrix": "authorisation",
    "test_object_level_access_boundaries": "object_access",
    "test_input_mutation_and_malformed_payloads": "input_mutation",
    "test_security_headers_on_representative_responses": "security_headers",
    "test_cors_controls": "cors",
    "test_rate_limit_behaviour": "resource_consumption",
    "test_dynamic_audit_events": "audit",
}


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Missing raw dynamic output: {path}")
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def pytest_summary(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    tests = payload.get("tests", [])
    categories: dict[str, dict[str, Any]] = {}
    for test in tests:
        nodeid = str(test.get("nodeid", ""))
        test_name = nodeid.rsplit("::", maxsplit=1)[-1]
        category = TEST_CATEGORY_BY_NAME.get(test_name, "uncategorised")
        item = categories.setdefault(
            category,
            {"category": category, "passed": 0, "failed": 0, "total": 0, "cases": []},
        )
        outcome = str(test.get("outcome", "unknown"))
        item["total"] += 1
        if outcome == "passed":
            item["passed"] += 1
        else:
            item["failed"] += 1
        item["cases"].append({"name": test_name, "outcome": outcome})
    return {
        "tool": "pytest",
        "execution_status": "completed" if payload.get("exitcode") == 0 else "failed",
        "total": int(payload.get("summary", {}).get("total", len(tests))),
        "passed": int(payload.get("summary", {}).get("passed", 0)),
        "failed": int(payload.get("summary", {}).get("failed", 0)),
        "categories": [categories[key] for key in sorted(categories)],
    }


def schemathesis_summary(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    checks = payload.get("checks", [])
    failures = [check for check in checks if check.get("outcome") != "passed"]
    return {
        "tool": "schemathesis",
        "execution_status": payload.get("execution_status", "completed"),
        "version": payload.get("version", "unknown"),
        "base_url": payload.get("base_url", "local"),
        "max_examples": payload.get("max_examples"),
        "request_timeout_seconds": payload.get("request_timeout_seconds"),
        "operation_count": payload.get("operation_count", 0),
        "case_count": payload.get("case_count", 0),
        "failed_count": len(failures),
        "checks": checks,
        "policy_decision": "fail" if failures else "pass",
    }


def zap_summary(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    alerts = (
        payload.get("site", [{}])[0].get("alerts", [])
        if "site" in payload
        else payload.get("alerts", [])
    )
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for alert in alerts:
        risk = str(alert.get("riskdesc", alert.get("risk", "Informational"))).split()[0]
        counts[risk if risk in counts else "Informational"] += 1
    return {
        "tool": "zap",
        "execution_status": payload.get("execution_status", "completed"),
        "version": payload.get("version", "unknown"),
        "scan_mode": payload.get("scan_mode", "baseline"),
        "target": payload.get("target", "local"),
        "alert_count": sum(counts.values()),
        "alerts_by_risk": counts,
        "policy_decision": "fail" if counts["High"] else "pass",
    }
