"""Sélection d'un petit lot de développement, pour tester la chaîne avant de
lancer les méthodes de qualification sur l'ensemble des alertes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from ..benchmark.models import ReferenceLabel
from .models import CodeQLAlert


@dataclass
class DevBatchEntry:
    alert: CodeQLAlert
    expected_verdict: str
    category: str


def select_dev_batch(
    alerts: Iterable[CodeQLAlert],
    labels_by_alert_id: Mapping[str, ReferenceLabel],
    category: str,
    true_positive_count: int,
    false_positive_count: int,
    exclude_alert_ids: frozenset[str] = frozenset(),
) -> list[DevBatchEntry]:
    """Sélectionne un petit lot déterministe pour une catégorie donnée.

    Les alertes candidates sont triées par ``alert_id`` avant d'être
    découpées : pour un même corpus et un même fichier de labels, la
    sélection renvoyée est toujours identique, ce qui est nécessaire pour
    que les tests sur ce lot restent reproductibles d'une exécution à
    l'autre.

    ``exclude_alert_ids`` retire des candidats les alertes déjà utilisées
    dans un autre lot (typiquement le lot de développement) : sans ça, le
    lot d'évaluation finale réutiliserait des cas qu'on a déjà regardés en
    détail pour régler le prompt ou la fenêtre de contexte, ce qui biaiserait
    le résultat en notre faveur.
    """
    candidates = [
        (alert, labels_by_alert_id[alert.alert_id])
        for alert in alerts
        if alert.alert_id in labels_by_alert_id
        and labels_by_alert_id[alert.alert_id].category == category
        and alert.alert_id not in exclude_alert_ids
    ]
    candidates.sort(key=lambda pair: pair[0].alert_id)

    true_positives = [c for c in candidates if c[1].expected_verdict == "true_positive"][:true_positive_count]
    false_positives = [c for c in candidates if c[1].expected_verdict == "false_positive"][:false_positive_count]

    return [
        DevBatchEntry(alert=alert, expected_verdict=label.expected_verdict, category=label.category)
        for alert, label in true_positives + false_positives
    ]
