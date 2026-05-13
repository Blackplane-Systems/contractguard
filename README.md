# contract-guard

`contract-guard` helps you find security and reliability issues in code, configs, queries, Dockerfiles, and dependency files without leaving VS Code.

## Features

- Scan the current file
- Scan the full workspace
- Show findings in a dedicated explorer view
- Publish inline diagnostics in the editor
- Export SARIF for external security workflows
- Show an overall security score in the status bar
- Filter low-confidence fixture/doc/test findings by default
- Continue scans when one analyzer has a runtime problem

## What it checks

- JSON schema inconsistencies
- SQL query risks and anti-patterns
- Regex complexity and ReDoS risks
- Hardcoded secrets
- PII exposure
- Insecure configuration
- Dockerfile issues
- Dependency vulnerabilities
- Python `requirements.txt` and `pyproject.toml`
- npm `package-lock.json` advisories from the bundled local database

## Commands

- `ContractGuard: Scan Workspace`
- `ContractGuard: Scan Current File`
- `ContractGuard: Export SARIF`
- `ContractGuard: Clear Findings`
- `ContractGuard: Install Python Runtime Dependencies`

## Requirements

- Python 3.11 or newer

If the Python runtime dependencies are missing, run:

- `ContractGuard: Install Python Runtime Dependencies`

## Extension Settings

- `contractguard.pythonPath`
- `contractguard.scanOnSave`
- `contractguard.scanDebounceMs`
- `contractguard.scanOnSaveScope`
- `contractguard.enabledAnalyzers`
- `contractguard.disabledRules`
- `contractguard.minimumConfidence`
- `contractguard.rulesDirectory`
- `contractguard.sqlExplainDatabase`

## Notes

- The extension runs analysis locally.
- The default minimum confidence is `medium`; use `low` for audit mode when you want sample/test fixtures included.
- SARIF export is available for CI and external security tooling.
