from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CodeQLAlert:
    alert_id: str
    language: str
    rule_id: str
    category: str | None
    message: str
    file_path: str
    start_line: int
    end_line: int
    code_flow: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class QualificationResult:
    alert_id: str
    language: str
    method: str
    verdict: str
    justification: str
    references: list[dict[str, Any]] = field(default_factory=list)
    missing_information: list[str] = field(default_factory=list)
    technical_status: str = "success"
    duration_ms: float | None = None
    model_calls: int = 0
    token_usage: dict[str, int] = field(default_factory=dict)
    prompt_version: str = "unversioned"
    config_version: str = "unversioned"


@dataclass
class TriageSession:
    alerts: list[CodeQLAlert] = field(default_factory=list)
    results: list[QualificationResult] = field(default_factory=list)

    def add_alert(self, alert: CodeQLAlert) -> None:
        self.alerts.append(alert)

    def add_result(self, result: QualificationResult) -> None:
        self.results.append(result)