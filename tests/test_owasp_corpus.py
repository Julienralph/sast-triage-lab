from sast_triage_lab.benchmark.owasp_corpus import build_reference_labels, load_expected_results
from sast_triage_lab.core.models import CodeQLAlert


def _write_expected_csv(tmp_path, rows):
    path = tmp_path / "expectedresults-0.1.csv"
    lines = ["# test name, category, real vulnerability, cwe, Benchmark version: 0.1"]
    lines.extend(",".join(row) for row in rows)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _alert(rule_id, file_path, index=0):
    return CodeQLAlert(
        alert_id=f"python:{rule_id}:{index}",
        language="python",
        rule_id=rule_id,
        category=None,
        message="",
        file_path=file_path,
        start_line=1,
        end_line=1,
    )


def test_load_expected_results_skips_header_and_non_test_rows(tmp_path):
    path = _write_expected_csv(tmp_path, [
        ["BenchmarkTest00001", "pathtraver", "true", "22"],
        ["not-a-test-case", "xss", "false", "79"],
    ])

    expected = load_expected_results(path)

    assert set(expected) == {"BenchmarkTest00001"}
    assert expected["BenchmarkTest00001"].real_vulnerability is True
    assert expected["BenchmarkTest00001"].category == "pathtraver"


def test_build_reference_labels_matches_rule_category_and_cwe(tmp_path):
    path = _write_expected_csv(tmp_path, [
        ["BenchmarkTest00001", "pathtraver", "true", "22"],
        ["BenchmarkTest00002", "pathtraver", "false", "22"],
    ])
    expected = load_expected_results(path)
    alerts = [
        _alert("py/path-injection", "testcode/BenchmarkTest00001.py", index=0),
        _alert("py/path-injection", "testcode/BenchmarkTest00002.py", index=1),
    ]

    labels = build_reference_labels(alerts, expected, "python")

    verdicts = {label.alert_id: label.expected_verdict for label in labels}
    assert verdicts["python:py/path-injection:0"] == "true_positive"
    assert verdicts["python:py/path-injection:1"] == "false_positive"


def test_build_reference_labels_ignores_rule_without_known_mapping(tmp_path):
    path = _write_expected_csv(tmp_path, [["BenchmarkTest00001", "pathtraver", "true", "22"]])
    expected = load_expected_results(path)
    alerts = [_alert("py/clear-text-logging-sensitive-data", "testcode/BenchmarkTest00001.py")]

    assert build_reference_labels(alerts, expected, "python") == []


def test_build_reference_labels_ignores_mismatched_category(tmp_path):
    # Le CSV attend `xss` pour ce cas de test, pas `pathtraver` : la règle
    # py/path-injection ne doit donc pas lui être reliée même si le nom du
    # fichier correspond à un cas de test connu.
    path = _write_expected_csv(tmp_path, [["BenchmarkTest00001", "xss", "true", "79"]])
    expected = load_expected_results(path)
    alerts = [_alert("py/path-injection", "testcode/BenchmarkTest00001.py")]

    assert build_reference_labels(alerts, expected, "python") == []


def test_build_reference_labels_ignores_alert_without_test_name(tmp_path):
    path = _write_expected_csv(tmp_path, [["BenchmarkTest00001", "pathtraver", "true", "22"]])
    expected = load_expected_results(path)
    alerts = [_alert("py/path-injection", "src/app/utils.py")]

    assert build_reference_labels(alerts, expected, "python") == []
