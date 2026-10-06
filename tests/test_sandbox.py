from pathlib import Path

import pytest

from sast_triage_lab.safety.sandbox import ReadOnlyRepository


def test_read_file_stays_inside_repository(tmp_path: Path):
    target = tmp_path / "target.py"
    target.write_text("line 1\nline 2\n", encoding="utf-8")

    repository = ReadOnlyRepository(tmp_path)

    assert repository.read_file("target.py") == "line 1\nline 2"


def test_path_traversal_is_blocked(tmp_path: Path):
    repository = ReadOnlyRepository(tmp_path)

    with pytest.raises(PermissionError):
        repository.read_file("../outside.py")


def test_large_read_is_rejected(tmp_path: Path):
    repository = ReadOnlyRepository(tmp_path)

    with pytest.raises(ValueError):
        repository.read_file("target.py", start_line=1, end_line=201)


def test_search_references_finds_matching_lines(tmp_path: Path):
    (tmp_path / "helpers.py").write_text(
        "def doSomething():\n    return 'moresafe'\n", encoding="utf-8",
    )
    repository = ReadOnlyRepository(tmp_path)

    matches = repository.search_references("doSomething")

    assert matches == [{"file_path": "helpers.py", "line": 1, "snippet": "def doSomething():"}]


def test_search_references_ignores_disallowed_extensions(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("doSomething appears here too\n", encoding="utf-8")
    repository = ReadOnlyRepository(tmp_path)

    assert repository.search_references("doSomething") == []


def test_search_references_stops_at_max_results(tmp_path: Path):
    (tmp_path / "many.py").write_text("\n".join("needle" for _ in range(10)), encoding="utf-8")
    repository = ReadOnlyRepository(tmp_path)

    assert len(repository.search_references("needle", max_results=3)) == 3


def test_search_references_rejects_empty_pattern(tmp_path: Path):
    repository = ReadOnlyRepository(tmp_path)

    with pytest.raises(ValueError):
        repository.search_references("")
