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
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
    "htmlcov",
    "target",
    "vendor",
    "site-packages",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
}

_NORMALIZED_SKIP_DIRS = {part.casefold() for part in _SKIP_DIRS}

_FIXTURE_DIRS = {
    "__tests__",
    "docs",
    "doc",
    "example",
    "examples",
    "fixture",
    "fixtures",
    "sample",
    "samples",
    "spec",
    "test",
    "tests",
}

_SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}

_DATA_EXTENSIONS = {
    ".csv",
    ".env",
    ".ini",
    ".json",
    ".jsonl",
    ".properties",
    ".toml",
    ".tsv",
    ".xml",
    ".yaml",
    ".yml",
}

_DOCUMENTATION_EXTENSIONS = {
    ".adoc",
    ".md",
    ".mdx",
    ".rst",
}

_INLINE_IGNORE_MARKERS = {
    "contractguard:ignore",
    "contractguard-ignore",
    "gitleaks:allow",
    "nosec",
    "pragma: allowlist secret",
}

DEFAULT_MAX_TEXT_FILE_BYTES = 1_000_000


def should_skip_path(path: Path) -> bool:
    parts = path.parts
    if path.exists() and path.is_file():
        parts = path.parent.parts
    elif path.suffix:
        parts = path.parent.parts
    return any(part.casefold() in _NORMALIZED_SKIP_DIRS for part in parts)


def should_skip_large_file(path: Path, max_bytes: int = DEFAULT_MAX_TEXT_FILE_BYTES) -> bool:
    try:
        return path.is_file() and path.stat().st_size > max_bytes
    except OSError:
        return True


def is_fixture_path(path: str | Path) -> bool:
    """Return true for docs/tests/samples where fixture-looking data is common."""
    file_path = Path(path)
    normalized = {part.casefold() for part in file_path.parts}
    name = file_path.name.casefold()
    return any(part in _FIXTURE_DIRS for part in normalized) or any(
        token in name for token in ("example", "fixture", "sample", "template")
    )


def is_source_file(path: str | Path) -> bool:
    return Path(path).suffix.casefold() in _SOURCE_EXTENSIONS


def is_data_file(path: str | Path) -> bool:
    file_path = Path(path)
    return file_path.suffix.casefold() in _DATA_EXTENSIONS or file_path.name.casefold() == ".env"


def is_documentation_file(path: str | Path) -> bool:
    return Path(path).suffix.casefold() in _DOCUMENTATION_EXTENSIONS


def has_inline_ignore(line: str) -> bool:
    lowered = line.casefold()
    return any(marker in lowered for marker in _INLINE_IGNORE_MARKERS)


def confidence_allowed(confidence: str, minimum: str) -> bool:
    order = {"low": 0, "medium": 1, "high": 2}
    return order.get(confidence, 2) >= order.get(minimum, 1)
