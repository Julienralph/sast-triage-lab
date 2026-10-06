"""Garde-fou qui limite le nombre d'appels au modèle et la durée d'une
exécution de qualification, pour ne jamais dépasser un budget fixé par
erreur (boucle infinie, bug, mauvais paramètre)."""

from __future__ import annotations

import time


class BudgetExceeded(RuntimeError):
    """Levée quand une exécution dépasserait son budget d'appels ou de durée."""


class CallBudget:
    """Plafond dur sur le nombre d'appels et, si fourni, la durée d'un run.

    Le contrôle se fait dans ``consume()``, appelé AVANT chaque appel réel
    au modèle, jamais après : le but est d'empêcher l'appel en trop, pas de
    constater le dépassement une fois qu'il a déjà eu lieu et facturé.
    """

    def __init__(self, max_calls: int, max_duration_seconds: float | None = None):
        if max_calls < 1:
            raise ValueError("max_calls doit être au moins 1")
        self.max_calls = max_calls
        self.max_duration_seconds = max_duration_seconds
        self.calls_made = 0
        self._started_at = time.monotonic()

    def consume(self) -> None:
        """Réserve un appel, ou lève BudgetExceeded si le budget est dépassé."""
        if self.calls_made >= self.max_calls:
            raise BudgetExceeded(
                f"Plafond de {self.max_calls} appels atteint "
                f"({self.calls_made} déjà effectués)."
            )
        if self.max_duration_seconds is not None:
            elapsed = time.monotonic() - self._started_at
            if elapsed >= self.max_duration_seconds:
                raise BudgetExceeded(
                    f"Plafond de durée de {self.max_duration_seconds}s atteint "
                    f"({elapsed:.1f}s écoulées)."
                )
        self.calls_made += 1

    def remaining(self) -> int:
        return self.max_calls - self.calls_made
