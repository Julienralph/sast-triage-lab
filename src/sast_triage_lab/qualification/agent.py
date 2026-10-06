"""Méthode « agent explorateur » : boucle d'outils, le modèle choisit quoi lire.

Contrairement à la méthode simple, on ne décide pas à l'avance de la
quantité de code à montrer : le modèle reçoit l'alerte avec un minimum de
contexte, et peut appeler `read_file` ou `search_references` autant de fois
que nécessaire (dans la limite du nombre de tours autorisé) avant de rendre
son verdict final via `submit_verdict`.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import anthropic

from ..core.interfaces import Qualifier
from ..core.models import CodeQLAlert, QualificationResult
from ..safety.budget import CallBudget
from ..safety.sandbox import ReadOnlyRepository

PROMPT_VERSION = "agent_v1"
_PROMPT_PATH = Path(__file__).resolve().parents[3] / "configs" / "prompts" / f"{PROMPT_VERSION}.md"

TOOLS: list[dict[str, Any]] = [
    {
        "name": "read_file",
        "description": (
            "Lit un extrait d'un fichier du depot analyse, entre deux numeros "
            "de ligne (200 lignes maximum). Chemin relatif a la racine du depot."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file_path", "start_line", "end_line"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "search_references",
        "description": (
            "Recherche une chaine de texte (nom de methode, de classe ou de "
            "variable) dans les fichiers source du depot, et renvoie les "
            "fichiers et lignes ou elle apparait."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
            "required": ["pattern"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "submit_verdict",
        "description": "Rend le verdict final sur l'alerte. A appeler une seule fois, quand on est pret a conclure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "uncertain"]},
                "justification": {"type": "string"},
                "missing_information": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["verdict", "justification", "missing_information"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


class ExploringAgentQualifier(Qualifier):
    """Boucle d'appels avec outils : le modèle décide lui-même quoi lire."""

    def __init__(
        self,
        client: anthropic.Anthropic,
        model: str,
        budget: CallBudget,
        repository: ReadOnlyRepository,
        max_turns: int = 5,
        transcripts_dir: Path | None = None,
    ):
        self.client = client
        self.model = model
        self.budget = budget
        self.repository = repository
        self.max_turns = max_turns
        self.transcripts_dir = transcripts_dir
        self.system_prompt = _PROMPT_PATH.read_text(encoding="utf-8")

    def qualify(self, alert: CodeQLAlert, initial_context: str) -> QualificationResult:
        messages: list[dict[str, Any]] = [{
            "role": "user",
            "content": (
                f"Rule: {alert.rule_id}\n"
                f"CodeQL message: {alert.message}\n"
                f"File: {alert.file_path} (lines {alert.start_line}-{alert.end_line})\n\n"
                f"Code:\n```\n{initial_context}\n```"
            ),
        }]

        started_at = time.monotonic()
        total_input_tokens = 0
        total_output_tokens = 0

        try:
            return self._run_loop(alert, messages, started_at, total_input_tokens, total_output_tokens)
        finally:
            # On sauvegarde la conversation complete quoi qu'il arrive :
            # verdict trouve, plafond de tours atteint, ou erreur API. Sans
            # ca, un cas bloque (comme celui qui a motive cette correction)
            # reste une boite noire, impossible a auditer apres coup.
            if self.transcripts_dir is not None:
                self._write_transcript(alert.alert_id, messages)

    def _run_loop(
        self,
        alert: CodeQLAlert,
        messages: list[dict[str, Any]],
        started_at: float,
        total_input_tokens: int,
        total_output_tokens: int,
    ) -> QualificationResult:
        for turn in range(self.max_turns):
            # Chaque tour de boucle = un appel reel a l'API = un cran du budget.
            self.budget.consume()

            try:
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=4096,
                    system=self.system_prompt,
                    tools=TOOLS,
                    messages=messages,
                )
            except anthropic.APIError as error:
                return QualificationResult(
                    alert_id=alert.alert_id, language=alert.language, method="agent",
                    verdict="uncertain", justification=f"Appel API en erreur : {error}",
                    technical_status="error",
                    duration_ms=(time.monotonic() - started_at) * 1000,
                    model_calls=turn + 1, prompt_version=PROMPT_VERSION,
                )

            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens
            messages.append({"role": "assistant", "content": response.content})

            verdict_call = next(
                (block for block in response.content if block.type == "tool_use" and block.name == "submit_verdict"),
                None,
            )
            if verdict_call is not None:
                data = verdict_call.input
                # Si la reponse a ete coupee par max_tokens en plein milieu de
                # l'appel a submit_verdict, les champs requis peuvent manquer
                # meme si le schema les declare obligatoires. On ne plante
                # pas : on renvoie un resultat clair plutot que de perdre tout
                # le lot en cours.
                if "verdict" not in data or "justification" not in data:
                    return QualificationResult(
                        alert_id=alert.alert_id, language=alert.language, method="agent",
                        verdict="uncertain",
                        justification="Reponse de submit_verdict incomplete (probablement coupee par max_tokens).",
                        technical_status="error",
                        duration_ms=(time.monotonic() - started_at) * 1000,
                        model_calls=turn + 1,
                        token_usage={"input": total_input_tokens, "output": total_output_tokens},
                        prompt_version=PROMPT_VERSION,
                    )
                return QualificationResult(
                    alert_id=alert.alert_id, language=alert.language, method="agent",
                    verdict=data["verdict"], justification=data["justification"],
                    missing_information=data.get("missing_information", []),
                    technical_status="success",
                    duration_ms=(time.monotonic() - started_at) * 1000,
                    model_calls=turn + 1,
                    token_usage={"input": total_input_tokens, "output": total_output_tokens},
                    prompt_version=PROMPT_VERSION,
                )

            tool_uses = [block for block in response.content if block.type == "tool_use"]
            if not tool_uses:
                # Ni outil, ni verdict : on le rappelle a l'ordre plutot que de planter.
                messages.append({
                    "role": "user",
                    "content": "Utilise submit_verdict pour rendre ton verdict final.",
                })
                continue

            messages.append({
                "role": "user",
                "content": [self._execute_tool(block) for block in tool_uses],
            })

        return QualificationResult(
            alert_id=alert.alert_id, language=alert.language, method="agent",
            verdict="uncertain",
            justification=f"Plafond de {self.max_turns} tours atteint sans verdict final.",
            technical_status="success",
            duration_ms=(time.monotonic() - started_at) * 1000,
            model_calls=self.max_turns,
            token_usage={"input": total_input_tokens, "output": total_output_tokens},
            prompt_version=PROMPT_VERSION,
        )

    def _execute_tool(self, block: Any) -> dict[str, Any]:
        try:
            if block.name == "read_file":
                content = self.repository.read_file(
                    block.input["file_path"],
                    start_line=block.input["start_line"],
                    end_line=block.input["end_line"],
                )
            elif block.name == "search_references":
                content = json.dumps(
                    self.repository.search_references(block.input["pattern"]),
                    ensure_ascii=False,
                )
            else:
                return {"type": "tool_result", "tool_use_id": block.id, "content": f"Outil inconnu : {block.name}", "is_error": True}
            return {"type": "tool_result", "tool_use_id": block.id, "content": content}
        except (FileNotFoundError, PermissionError, ValueError, KeyError) as error:
            return {"type": "tool_result", "tool_use_id": block.id, "content": str(error), "is_error": True}

    def _write_transcript(self, alert_id: str, messages: list[dict[str, Any]]) -> None:
        self.transcripts_dir.mkdir(parents=True, exist_ok=True)
        safe_name = alert_id.replace(":", "_").replace("/", "_")
        path = self.transcripts_dir / f"{safe_name}.json"
        path.write_text(
            json.dumps(_serialize_messages(messages), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


def _serialize_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convertit la conversation en structures JSON ordinaires.

    Les messages qu'on construit nous-memes (listes/dicts) passent tels
    quels. Les blocs renvoyes par le SDK Anthropic (TextBlock, ToolUseBlock,
    ...) sont des objets Pydantic : on les convertit via ``model_dump()``,
    recursivement, pour pouvoir relire la conversation plus tard sans avoir
    besoin du SDK installe.
    """
    def convert(value: Any) -> Any:
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, list):
            return [convert(item) for item in value]
        if isinstance(value, dict):
            return {key: convert(item) for key, item in value.items()}
        if hasattr(value, "model_dump"):
            return convert(value.model_dump())
        return str(value)

    return [convert(message) for message in messages]
