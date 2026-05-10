# contract-guard

`contract-guard` helps you find security and reliability issues in code, configs, queries, Dockerfiles, and dependency files without leaving VS Code.

## Features

- Scan the current file
- Scan the full workspace
- Show findings in a dedicated explorer view
- Publish inline diagnostics in the editor
- Export SARIF for external security workflows
- Show an overall security score in the status bar

## What it checks

- JSON schema inconsistencies
- SQL query risks and anti-patterns
- Regex complexity and ReDoS risks
- Hardcoded secrets
- PII exposure
- Insecure configuration
- Dockerfile issues
- Dependency vulnerabilities

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
- `contractguard.enabledAnalyzers`
- `contractguard.disabledRules`
- `contractguard.rulesDirectory`
- `contractguard.sqlExplainDatabase`

## Notes

- The extension runs analysis locally.
- SARIF export is available for CI and external security tooling.
