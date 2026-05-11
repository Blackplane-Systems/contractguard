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

_NORMALIZED_SKIP_DIRS = {part.casefold() for part in _SKIP_DIRS}


def should_skip_path(path: Path) -> bool:
    parts = path.parts
    if path.exists() and path.is_file():
        parts = path.parent.parts
    elif path.suffix:
        parts = path.parent.parts
    return any(part.casefold() in _NORMALIZED_SKIP_DIRS for part in parts)
