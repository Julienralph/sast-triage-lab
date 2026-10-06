import pytest

from sast_triage_lab.safety.budget import BudgetExceeded, CallBudget


def test_call_budget_allows_up_to_the_limit():
    budget = CallBudget(max_calls=2)

    budget.consume()
    budget.consume()

    assert budget.calls_made == 2
    assert budget.remaining() == 0


def test_call_budget_blocks_the_call_over_the_limit():
    budget = CallBudget(max_calls=1)
    budget.consume()

    with pytest.raises(BudgetExceeded):
        budget.consume()

    # L'appel refuse ne doit pas etre compte comme effectue.
    assert budget.calls_made == 1


def test_call_budget_blocks_once_duration_is_exceeded(monkeypatch):
    # Premiere valeur consommee par le constructeur (depart du chrono),
    # seconde valeur consommee par le premier consume() (10s plus tard).
    clock = iter([0.0, 10.0])
    monkeypatch.setattr("sast_triage_lab.safety.budget.time.monotonic", lambda: next(clock))

    budget = CallBudget(max_calls=5, max_duration_seconds=5)

    with pytest.raises(BudgetExceeded):
        budget.consume()


def test_max_calls_must_be_at_least_one():
    with pytest.raises(ValueError):
        CallBudget(max_calls=0)
