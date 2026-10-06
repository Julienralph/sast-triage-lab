import json

from sast_triage_lab.sarif.parser import load_sarif


def test_sarif_result_is_normalized(tmp_path):
    sarif = {
        "runs": [{
            "tool": {"driver": {"rules": [{"id": "py/test", "properties": {"tags": ["CWE-22"]}}]}},
            "results": [{
                "ruleId": "py/test",
                "message": {"text": "unsafe path"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "app.py"},
                    "region": {"startLine": 4, "endLine": 5},
                }}],
            }],
        }]
    }
    path = tmp_path / "results.sarif"
    path.write_text(json.dumps(sarif), encoding="utf-8")

    alert = load_sarif(path, "python")[0]

    assert alert.rule_id == "py/test"
    assert alert.category == "CWE-22"
    assert alert.file_path == "app.py"
    assert alert.start_line == 4
