from __future__ import annotations

from abc import ABC, abstractmethod

from .models import CodeQLAlert, QualificationResult


class Qualifier(ABC):
    """Common contract for both experimental qualification methods."""

    @abstractmethod
    def qualify(self, alert: CodeQLAlert, initial_context: str) -> QualificationResult:
        raise NotImplementedError