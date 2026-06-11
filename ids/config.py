from __future__ import annotations

from pathlib import Path


def load_blocklist(path: str | Path) -> set[str]:
    """Load newline-separated indicators from a text file.

    Empty lines and lines starting with # are ignored.
    """
    file_path = Path(path)
    if not file_path.exists():
        return set()

    values: set[str] = set()
    for line in file_path.read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if item and not item.startswith("#"):
            values.add(item.lower())
    return values
