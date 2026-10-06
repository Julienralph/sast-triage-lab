import pytest

from sast_triage_lab.core.models import CodeQLAlert
from sast_triage_lab.qualification.agent import ExploringAgentQualifier
from sast_triage_lab.safety.budget import BudgetExceeded, CallBudget
from sast_triage_lab.safety.sandbox import ReadOnlyRepository


class _FakeUsage:
    def __init__(self, input_tokens=50, output_tokens=20):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeToolUseBlock:
    type = "tool_use"

    def __init__(self, name, input_, block_id="tool_1"):
        self.name = name
        self.input = input_
        self.id = block_id

    def model_dump(self):
        # Imite le comportement reel des blocs du SDK Anthropic (objets
        # Pydantic), pour que le test de transcription soit realiste.
        return {"type": self.type, "name": self.name, "input": self.input, "id": self.id}


class _FakeResponse:
    def __init__(self, content):
        self.content = content
        self.usage = _FakeUsage()


class _FakeMessages:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._responses.pop(0)


class _FakeClient:
    def __init__(self, responses):
        self.messages = _FakeMessages(responses)


def _alert() -> CodeQLAlert:
    return CodeQLAlert(
        alert_id="java:java/path-injection:0", language="java", rule_id="java/path-injection",
        category=None, message="tainted path", file_path="Test.java",
        start_line=10, end_line=10,
    )


def test_agent_reads_a_file_then_submits_verdict(tmp_path):
    (tmp_path / "Helper.java").write_text(
        "class Helper {\n    String doSomething() { return \"moresafe\"; }\n}\n",
        encoding="utf-8",
    )
    repository = ReadOnlyRepository(tmp_path)
    responses = [
        _FakeResponse([_FakeToolUseBlock(
            "read_file", {"file_path": "Helper.java", "start_line": 1, "end_line": 3}, "t1",
        )]),
        _FakeResponse([_FakeToolUseBlock("submit_verdict", {
            "verdict": "false_positive",
            "justification": "La valeur retournee est toujours la constante 'moresafe'.",
            "missing_information": [],
        }, "t2")]),
    ]
    client = _FakeClient(responses)
    budget = CallBudget(max_calls=5)
    agent = ExploringAgentQualifier(client=client, model="claude-sonnet-5", budget=budget, repository=repository)

    result = agent.qualify(_alert(), "String bar = helper.doSomething();")

    assert result.verdict == "false_positive"
    assert result.model_calls == 2
    assert budget.calls_made == 2

    # Le deuxieme appel doit bien transporter le resultat de la lecture du premier tour.
    second_call_messages = client.messages.calls[1]["messages"]
    tool_result_message = next(m for m in second_call_messages if m["role"] == "user" and isinstance(m["content"], list))
    assert tool_result_message["content"][0]["tool_use_id"] == "t1"
    assert "moresafe" in tool_result_message["content"][0]["content"]


def test_agent_handles_truncated_submit_verdict_without_crashing(tmp_path):
    # Simule une reponse coupee par max_tokens : le tool_use "submit_verdict"
    # existe, mais son input n'a pas la cle "justification".
    repository = ReadOnlyRepository(tmp_path)
    responses = [_FakeResponse([_FakeToolUseBlock("submit_verdict", {"verdict": "uncertain"}, "t1")])]
    client = _FakeClient(responses)
    budget = CallBudget(max_calls=5)
    agent = ExploringAgentQualifier(client=client, model="claude-sonnet-5", budget=budget, repository=repository)

    result = agent.qualify(_alert(), "...")

    assert result.technical_status == "error"
    assert result.verdict == "uncertain"
    assert result.model_calls == 1


def test_agent_saves_full_transcript_even_when_turn_cap_is_reached(tmp_path):
    repository = ReadOnlyRepository(tmp_path)
    transcripts_dir = tmp_path / "transcripts"
    responses = [
        _FakeResponse([_FakeToolUseBlock("search_references", {"pattern": "x"}, f"t{i}")])
        for i in range(3)
    ]
    client = _FakeClient(responses)
    budget = CallBudget(max_calls=10)
    agent = ExploringAgentQualifier(
        client=client, model="claude-sonnet-5", budget=budget, repository=repository,
        max_turns=3, transcripts_dir=transcripts_dir,
    )

    agent.qualify(_alert(), "contexte initial")

    transcript_path = transcripts_dir / "java_java_path-injection_0.json"
    assert transcript_path.exists()

    import json
    transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    # Le premier message (le contexte envoye) et les 3 tours doivent y etre.
    assert transcript[0]["role"] == "user"
    assert "contexte initial" in transcript[0]["content"]
    assert len(transcript) == 1 + 3 * 2  # 1 message initial + (assistant, tool_result) par tour


def test_agent_stops_when_budget_is_exhausted(tmp_path):
    repository = ReadOnlyRepository(tmp_path)
    responses = [_FakeResponse([_FakeToolUseBlock("search_references", {"pattern": "x"}, "t1")])]
    client = _FakeClient(responses)
    budget = CallBudget(max_calls=1)
    agent = ExploringAgentQualifier(client=client, model="claude-sonnet-5", budget=budget, repository=repository)

    with pytest.raises(BudgetExceeded):
        agent.qualify(_alert(), "...")


def test_agent_returns_uncertain_when_turn_cap_is_reached(tmp_path):
    repository = ReadOnlyRepository(tmp_path)
    responses = [
        _FakeResponse([_FakeToolUseBlock("search_references", {"pattern": "x"}, f"t{i}")])
        for i in range(3)
    ]
    client = _FakeClient(responses)
    budget = CallBudget(max_calls=10)
    agent = ExploringAgentQualifier(
        client=client, model="claude-sonnet-5", budget=budget, repository=repository, max_turns=3,
    )

    result = agent.qualify(_alert(), "...")

    assert result.verdict == "uncertain"
    assert "Plafond" in result.justification
    assert result.model_calls == 3


def test_agent_reports_technical_error_on_api_failure(tmp_path):
    import anthropic
    import httpx2

    class _FailingMessages:
        def create(self, **kwargs):
            raise anthropic.APIConnectionError(
                message="boom",
                request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"),
            )

    class _FailingClient:
        def __init__(self):
            self.messages = _FailingMessages()

    repository = ReadOnlyRepository(tmp_path)
    budget = CallBudget(max_calls=5)
    agent = ExploringAgentQualifier(client=_FailingClient(), model="claude-sonnet-5", budget=budget, repository=repository)

    result = agent.qualify(_alert(), "...")

    assert result.technical_status == "error"
    assert result.verdict == "uncertain"
