from __future__ import annotations

from pathlib import Path

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "dist-vsix",
    "build",
    "out",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
}


def should_skip_path(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)
