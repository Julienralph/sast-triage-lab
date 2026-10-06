from sast_triage_lab.benchmark.models import ReferenceLabel
from sast_triage_lab.core.dev_batch import select_dev_batch
from sast_triage_lab.core.models import CodeQLAlert


def _alert(alert_id: str) -> CodeQLAlert:
    return CodeQLAlert(
        alert_id=alert_id,
        language="python",
        rule_id="py/path-injection",
        category=None,
        message="",
        file_path=f"testcode/{alert_id}.py",
        start_line=1,
        end_line=1,
    )


def test_select_dev_batch_is_deterministic_and_respects_counts():
    alerts = [_alert(f"a{i}") for i in range(6)]
    labels = {
        "a0": ReferenceLabel("a0", "true_positive", "owasp", "pathtraver"),
        "a1": ReferenceLabel("a1", "true_positive", "owasp", "pathtraver"),
        "a2": ReferenceLabel("a2", "true_positive", "owasp", "pathtraver"),
        "a3": ReferenceLabel("a3", "false_positive", "owasp", "pathtraver"),
        "a4": ReferenceLabel("a4", "false_positive", "owasp", "pathtraver"),
        "a5": ReferenceLabel("a5", "false_positive", "owasp", "xss"),  # autre catégorie, doit être ignorée
    }

    batch = select_dev_batch(alerts, labels, "pathtraver", true_positive_count=2, false_positive_count=1)

    assert [entry.alert.alert_id for entry in batch] == ["a0", "a1", "a3"]
    assert [entry.expected_verdict for entry in batch] == [
        "true_positive", "true_positive", "false_positive",
    ]


def test_select_dev_batch_is_stable_across_calls():
    alerts = [_alert(f"a{i}") for i in range(4)]
    labels = {f"a{i}": ReferenceLabel(f"a{i}", "true_positive", "owasp", "pathtraver") for i in range(4)}

    first = select_dev_batch(alerts, labels, "pathtraver", true_positive_count=2, false_positive_count=0)
    second = select_dev_batch(alerts, labels, "pathtraver", true_positive_count=2, false_positive_count=0)

    assert [e.alert.alert_id for e in first] == [e.alert.alert_id for e in second]
