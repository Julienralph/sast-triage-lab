from __future__ import annotations

from pathlib import Path
from typing import Any


class ReadOnlyRepository:
    """Expose bounded reads while blocking path traversal and symlinks."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def read_file(self, relative_path: str, start_line: int = 1, end_line: int = 80) -> str:
        candidate = self.root / relative_path
        if candidate.is_symlink():
            raise PermissionError("Symbolic links are not allowed")
        candidate = candidate.resolve()
        if self.root not in candidate.parents:
            raise PermissionError("Path is outside the authorized repository")

        if start_line < 1 or end_line < start_line or end_line - start_line >= 200:
            raise ValueError("Invalid or oversized line range")

        if not candidate.is_file():
            raise FileNotFoundError(relative_path)
        lines = candidate.read_text(encoding="utf-8").splitlines()
        return "\n".join(lines[start_line - 1:end_line])

    def search_references(
        self,
        pattern: str,
        max_results: int = 20,
        extensions: tuple[str, ...] = (".java", ".py"),
    ) -> list[dict[str, Any]]:
        """Cherche une sous-chaîne dans les fichiers source du dépôt.

        Ne parcourt que les fichiers sous ``self.root`` dont l'extension est
        autorisée, ignore les liens symboliques (même garde-fou que
        ``read_file``) et les fichiers illisibles en UTF-8 (probablement
        binaires), et s'arrête dès que ``max_results`` correspondances sont
        trouvées.
        """
        if not pattern:
            raise ValueError("pattern must not be empty")

        matches: list[dict[str, Any]] = []
        for candidate in sorted(self.root.rglob("*")):
            if len(matches) >= max_results:
                break
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.suffix not in extensions:
                continue
            resolved = candidate.resolve()
            if self.root not in resolved.parents:
                continue
            try:
                lines = resolved.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue

            for line_number, line in enumerate(lines, start=1):
                if pattern in line:
                    matches.append({
                        "file_path": candidate.relative_to(self.root).as_posix(),
                        "line": line_number,
                        "snippet": line.strip(),
                    })
                    if len(matches) >= max_results:
                        break
        return matches