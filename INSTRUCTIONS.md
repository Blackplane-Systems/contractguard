# ContractGuard Usage

## CLI

```powershell
.\.venv\Scripts\python.exe -m contractguard.cli analyze --type all --path . --score
.\.venv\Scripts\python.exe -m contractguard.cli analyze --type secrets --path . --report-sarif contractguard.sarif
.\.venv\Scripts\python.exe -m contractguard.cli analyze --type all --path . --min-confidence low --score
```

## Bridge

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
.\.venv\Scripts\python.exe -m contractguard.bridge scan --path . --analyzer all --include-sarif
.\.venv\Scripts\python.exe -m contractguard.bridge scan --path . --analyzer all --min-confidence medium
```

## VS Code

1. Build the extension with `tsc`.
2. Install the generated VSIX.
3. Run `ContractGuard: Install Python Runtime Dependencies` if the runtime is missing.
4. Use `ContractGuard: Scan Workspace` or enable scan-on-save.
