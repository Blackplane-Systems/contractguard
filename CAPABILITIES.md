# Capabilities Reference

## Core engine

- Rule-driven analyzer execution
- Shared findings and severity model
- Security scoring and grade calculation
- HTML reporting
- SARIF 2.1.0 export
- Scan history storage
- Machine-readable bridge for editor integration
- Confidence-aware filtering for fixtures, tests, docs, and generated-looking data
- Per-analyzer runtime isolation so one failed analyzer does not abort the whole scan

## VS Code integration

- Workspace and file scan commands
- Diagnostics per file
- Findings explorer
- Status bar score
- Scan-on-save
- SARIF export command
- Disabled-rule filtering in the client
- Minimum-confidence filtering in the client

## Dependency coverage

- Python requirements files
- Python `pyproject.toml` dependencies
- npm `package-lock.json` dependencies
- Static local advisory database for offline use

## Non-goals in this repository

- No web upload UI
- No CSV analyzer
- No duplicate extension and CLI logic paths
- No live package-advisory network lookup
