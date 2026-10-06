from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping

from ..core.models import QualificationResult
from .models import ReferenceLabel


def confusion_counts(
    results: Iterable[QualificationResult],
    labels: Mapping[str, ReferenceLabel],
) -> Counter[tuple[str, str]]:
    counts: Counter[tuple[str, str]] = Counter()
    for result in results:
        label = labels.get(result.alert_id)
        if label is not None:
            counts[(label.expected_verdict, result.verdict)] += 1
    return counts


def technical_failures(results: Iterable[QualificationResult]) -> int:
    return sum(result.technical_status != "success" for result in results)