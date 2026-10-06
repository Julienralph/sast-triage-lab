from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.models import CodeQLAlert


def load_sarif(path: Path, language: str) -> list[CodeQLAlert]:
    """Convert CodeQL SARIF results into the generic alert model."""
    document = json.loads(path.read_text(encoding="utf-8"))
    alerts: list[CodeQLAlert] = []
    for run in document.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if rule.get("id")
        }
        for index, result in enumerate(run.get("results", [])):
            location = _first_location(result)
            rule_id = result.get("ruleId", "unknown-rule")
            alerts.append(CodeQLAlert(
                alert_id=f"{language}:{rule_id}:{index}",
                language=language,
                rule_id=rule_id,
                category=_category(rules.get(rule_id, {})),
                message=result.get("message", {}).get("text", ""),
                file_path=location["file_path"],
                start_line=location["start_line"],
                end_line=location["end_line"],
                code_flow=result.get("codeFlows", []),
            ))
    return alerts


def _first_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations", [])
    physical = locations[0].get("physicalLocation", {}) if locations else {}
    region = physical.get("region", {})
    return {
        "file_path": physical.get("artifactLocation", {}).get("uri", "unknown"),
        "start_line": region.get("startLine", 0),
        "end_line": region.get("endLine", region.get("startLine", 0)),
    }


def _category(rule: dict[str, Any]) -> str | None:
    tags = rule.get("properties", {}).get("tags", [])
    return next((tag for tag in tags if str(tag).startswith("CWE-")), None)