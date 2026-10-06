from sast_triage_lab.benchmark.metrics import confusion_counts, technical_failures
from sast_triage_lab.benchmark.models import ReferenceLabel
from sast_triage_lab.core.models import QualificationResult


def test_metrics_keep_verdict_counts_and_failures_visible():
    results = [
        QualificationResult("a", "python", "simple", "false_positive", "", technical_status="success"),
        QualificationResult("b", "python", "agent", "uncertain", "", technical_status="error"),
    ]
    labels = {
        "a": ReferenceLabel("a", "false_positive", "owasp"),
        "b": ReferenceLabel("b", "true_positive", "owasp"),
    }

    assert confusion_counts(results, labels)[("false_positive", "false_positive")] == 1
    assert confusion_counts(results, labels)[("true_positive", "uncertain")] == 1
    assert technical_failures(results) == 1
