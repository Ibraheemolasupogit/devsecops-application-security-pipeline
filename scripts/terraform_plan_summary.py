"""Summarise a saved Terraform plan JSON without exposing its full values."""

from __future__ import annotations

import json
import sys


def main() -> int:
    try:
        plan = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"Invalid Terraform plan JSON: {error}", file=sys.stderr)
        return 2
    counts = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0, "other": 0}
    for resource in plan.get("resource_changes", []):
        actions = resource.get("change", {}).get("actions", [])
        if actions == ["create"]:
            counts["create"] += 1
        elif actions == ["update"]:
            counts["update"] += 1
        elif actions == ["delete"]:
            counts["delete"] += 1
        elif actions in (["delete", "create"], ["create", "delete"]):
            counts["replace"] += 1
        elif actions == ["no-op"]:
            counts["no-op"] += 1
        else:
            counts["other"] += 1
    print(json.dumps(counts, sort_keys=True, indent=2))
    if counts["update"] or counts["delete"] or counts["replace"] or counts["other"]:
        print(
            "STOP: the plan contains an update, deletion, replacement, or unknown action",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
