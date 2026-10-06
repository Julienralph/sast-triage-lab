"""Jointure entre les alertes CodeQL et les labels OWASP Benchmark."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from ..core.models import CodeQLAlert
from .models import ReferenceLabel
from .owasp_rules import RULE_CATEGORY_MAP

_TEST_NAME = re.compile(r"BenchmarkTest\d+")


@dataclass
class ExpectedResult:
    """Une ligne du fichier ``expectedresults-*.csv`` d'OWASP Benchmark."""

    test_name: str
    category: str
    cwe: str
    real_vulnerability: bool


def load_expected_results(csv_path: Path) -> dict[str, ExpectedResult]:
    """Charge les labels OWASP Benchmark, indexés par nom de cas de test.

    Le fichier a une première ligne commentée (``#...``) suivie de lignes
    ``test_name,category,real_vulnerability,cwe``. Seules les lignes dont le
    nom correspond à ``BenchmarkTestNNNNN`` sont conservées.
    """
    expected: dict[str, ExpectedResult] = {}
    with csv_path.open(encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if not row or row[0].startswith("#"):
                continue
            test_name, category, real_vulnerability, cwe = row[:4]
            if not _TEST_NAME.fullmatch(test_name):
                continue
            expected[test_name] = ExpectedResult(
                test_name=test_name,
                category=category,
                cwe=cwe,
                real_vulnerability=real_vulnerability.strip().lower() == "true",
            )
    return expected


def _test_name_from_path(file_path: str) -> str | None:
    match = _TEST_NAME.search(file_path)
    return match.group(0) if match else None


def build_reference_labels(
    alerts: Iterable[CodeQLAlert],
    expected: Mapping[str, ExpectedResult],
    language: str,
    rule_map: Mapping[str, tuple[str, str]] | None = None,
) -> list[ReferenceLabel]:
    """Relie des alertes CodeQL à leurs labels OWASP Benchmark.

    Une alerte n'est retenue que si :

    1. sa règle a une correspondance connue dans ``rule_map`` (voir
       ``owasp_rules.RULE_CATEGORY_MAP``) ;
    2. son fichier correspond à un cas de test labellisé ;
    3. la catégorie et le CWE attendus pour ce cas de test correspondent
       exactement à ceux de la règle.

    Les alertes qui ne remplissent pas ces conditions sont ignorées : elles
    n'ont pas de vérité de référence exploitable pour l'évaluation, ce n'est
    pas une erreur de jointure.
    """
    rule_map = rule_map if rule_map is not None else RULE_CATEGORY_MAP.get(language, {})
    labels: list[ReferenceLabel] = []
    for alert in alerts:
        mapped = rule_map.get(alert.rule_id)
        if mapped is None:
            continue
        test_name = _test_name_from_path(alert.file_path)
        if test_name is None:
            continue
        label = expected.get(test_name)
        if label is None:
            continue
        if (label.category, label.cwe) != mapped:
            continue
        verdict = "true_positive" if label.real_vulnerability else "false_positive"
        labels.append(ReferenceLabel(
            alert_id=alert.alert_id,
            expected_verdict=verdict,
            source=f"owasp-benchmark-{language}",
            category=label.category,
        ))
    return labels
