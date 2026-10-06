import anthropic
import httpx2
import pytest

from sast_triage_lab.core.models import CodeQLAlert
from sast_triage_lab.qualification.simple import SimpleQualifier, SimpleVerdict
from sast_triage_lab.safety.budget import BudgetExceeded, CallBudget


class _FakeUsage:
    def __init__(self, input_tokens: int, output_tokens: int):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens


class _FakeResponse:
    def __init__(self, parsed_output, input_tokens=100, output_tokens=40):
        self.parsed_output = parsed_output
        self.usage = _FakeUsage(input_tokens, output_tokens)


class _FakeMessages:
    def __init__(self, response):
        self._response = response
        self.last_call_kwargs = None

    def parse(self, **kwargs):
        self.last_call_kwargs = kwargs
        return self._response


class _FakeClient:
    def __init__(self, response):
        self.messages = _FakeMessages(response)


class _FailingMessages:
    def parse(self, **kwargs):
        raise anthropic.APIConnectionError(
            message="boom",
            request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"),
        )


class _FailingClient:
    def __init__(self):
        self.messages = _FailingMessages()


def _alert() -> CodeQLAlert:
    return CodeQLAlert(
        alert_id="python:py/path-injection:0",
        language="python",
        rule_id="py/path-injection",
        category=None,
        message="tainted path",
        file_path="testcode/BenchmarkTest00001.py",
        start_line=10,
        end_line=10,
    )


def test_simple_qualifier_returns_successful_result():
    verdict = SimpleVerdict(verdict="true_positive", justification="Tainted value reaches the sink unchecked.")
    client = _FakeClient(_FakeResponse(verdict))
    budget = CallBudget(max_calls=5)
    qualifier = SimpleQualifier(client=client, model="claude-sonnet-5", budget=budget)

    result = qualifier.qualify(_alert(), "fileName = base + param\nopen(fileName)")

    assert result.verdict == "true_positive"
    assert result.technical_status == "success"
    assert result.model_calls == 1
    assert result.token_usage == {"input": 100, "output": 40}
    assert budget.calls_made == 1


def test_simple_qualifier_stops_when_budget_is_exhausted():
    verdict = SimpleVerdict(verdict="uncertain", justification="n/a")
    client = _FakeClient(_FakeResponse(verdict))
    budget = CallBudget(max_calls=1)
    qualifier = SimpleQualifier(client=client, model="claude-sonnet-5", budget=budget)

    qualifier.qualify(_alert(), "...")

    with pytest.raises(BudgetExceeded):
        qualifier.qualify(_alert(), "...")


def test_simple_qualifier_reports_technical_error_on_api_failure():
    budget = CallBudget(max_calls=5)
    qualifier = SimpleQualifier(client=_FailingClient(), model="claude-sonnet-5", budget=budget)

    result = qualifier.qualify(_alert(), "...")

    assert result.technical_status == "error"
    assert result.verdict == "uncertain"
    # L'appel a bien ete tente (et consomme le budget), meme s'il a echoue.
    assert budget.calls_made == 1
