"""Méthode « appel simple » : un seul message au modèle, sans outils.

C'est la méthode de référence à laquelle l'agent explorateur (à venir) sera
comparé : le modèle doit juger uniquement à partir du contexte fourni en
entrée, sans pouvoir demander à lire davantage de code.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Literal

import anthropic
from pydantic import BaseModel

from ..core.interfaces import Qualifier
from ..core.models import CodeQLAlert, QualificationResult
from ..safety.budget import CallBudget

PROMPT_VERSION = "simple_v1"
_PROMPT_PATH = Path(__file__).resolve().parents[3] / "configs" / "prompts" / f"{PROMPT_VERSION}.md"


class SimpleVerdict(BaseModel):
    """Forme JSON exacte qu'on force le modèle à renvoyer (structured output)."""

    verdict: Literal["true_positive", "false_positive", "uncertain"]
    justification: str
    missing_information: list[str] = []


class SimpleQualifier(Qualifier):
    """Envoie l'alerte et son contexte en un seul message, sans boucle d'outils."""

    def __init__(self, client: anthropic.Anthropic, model: str, budget: CallBudget):
        self.client = client
        self.model = model
        self.budget = budget
        self.system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")

    def qualify(self, alert: CodeQLAlert, initial_context: str) -> QualificationResult:
        # Verifie le plafond AVANT d'envoyer la requete : si depasse, leve
        # BudgetExceeded et n'appelle jamais l'API.
        self.budget.consume()

        user_message = (
            f"Rule: {alert.rule_id}\n"
            f"CodeQL message: {alert.message}\n"
            f"File: {alert.file_path} (lines {alert.start_line}-{alert.end_line})\n\n"
            f"Code:\n```\n{initial_context}\n```"
        )

        started_at = time.monotonic()
        try:
            response = self.client.messages.parse(
                model=self.model,
                max_tokens=1024,
                system=self.system_prompt,
                messages=[{"role": "user", "content": user_message}],
                output_format=SimpleVerdict,
            )
        except anthropic.APIError as error:
            return QualificationResult(
                alert_id=alert.alert_id,
                language=alert.language,
                method="simple",
                verdict="uncertain",
                justification=f"Appel API en erreur : {error}",
                technical_status="error",
                duration_ms=(time.monotonic() - started_at) * 1000,
                model_calls=1,
                prompt_version=PROMPT_VERSION,
            )

        duration_ms = (time.monotonic() - started_at) * 1000
        verdict = response.parsed_output

        return QualificationResult(
            alert_id=alert.alert_id,
            language=alert.language,
            method="simple",
            verdict=verdict.verdict,
            justification=verdict.justification,
            missing_information=verdict.missing_information,
            technical_status="success",
            duration_ms=duration_ms,
            model_calls=1,
            token_usage={
                "input": response.usage.input_tokens,
                "output": response.usage.output_tokens,
            },
            prompt_version=PROMPT_VERSION,
        )
