# ContractGuard for VS Code

ContractGuard is a VS Code extension backed by a Python security analysis core. It scans source trees for schema drift, risky SQL, regex complexity, secrets, PII, insecure configuration, Dockerfile issues, and vulnerable dependencies, then surfaces the results as diagnostics, a findings explorer, a status bar score, and SARIF exports.

## What ships in this repository

- A reusable Python engine in `src/contractguard` with rule-driven analyzers, scoring, findings, history, and SARIF generation.
- A VS Code extension in `vscode-src` that runs the engine in a separate Python process and renders results inside the editor.
- Rules in `rules/` that stay bundled with the extension and CLI.

## Supported analyzers

- JSON schema analysis
- SQL analysis
- Regex complexity analysis
- Secrets detection
- PII detection
- Config security analysis
- Dockerfile linting
- Dependency vulnerability analysis

## VS Code features

- `ContractGuard: Scan Workspace`
- `ContractGuard: Scan Current File`
- `ContractGuard: Export SARIF`
- `ContractGuard: Clear Findings`
- Findings tree view grouped by severity
- Inline diagnostics and quick navigation
- Status bar security grade
- Debounced scan-on-save
- Configurable analyzer set and disabled rules

## Runtime requirements

- Python 3.11+ available on the machine running VS Code
- Python packages from `python-requirements.txt`

For local development in this repository:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r python-requirements.txt
```

## Development commands

Python:

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m contractguard.bridge scan --path . --analyzer all --include-sarif
```

Extension:

```powershell
node .\node_modules\typescript\bin\tsc -p .\tsconfig.json
node .\node_modules\@vscode\vsce\vsce package
```

## Settings

- `contractguard.pythonPath`
- `contractguard.scanOnSave`
- `contractguard.scanDebounceMs`
- `contractguard.enabledAnalyzers`
- `contractguard.disabledRules`
- `contractguard.rulesDirectory`
- `contractguard.sqlExplainDatabase`

## Packaging

The extension is packaged from the repository root. The VSIX includes the compiled extension, bundled Python source, rules, and documentation. The output artifact is written to `dist-vsix/`.
