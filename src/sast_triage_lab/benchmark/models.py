from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ReferenceLabel:
    alert_id: str
    expected_verdict: str
    source: str
    category: str | None = None