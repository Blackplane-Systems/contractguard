# Deployment Notes

## Marketplace packaging

The extension is packaged from the repository root with `vsce`. The package includes:

- `dist/` compiled extension entrypoint
- `src/contractguard/` Python engine
- `rules/` bundled rule files
- `media/` extension assets
- `python-requirements.txt` runtime dependency list

## Runtime model

ContractGuard runs its analyzers out of process through `python -m contractguard.bridge`. The extension sets `PYTHONPATH` to its bundled `src/` directory so the engine can run without a separate package install step inside the extension host.

The 2.0 scanner filters low-confidence fixture findings by default and reports analyzer runtime failures as findings instead of aborting an entire workspace scan.

## Publish checklist

1. Build the extension with `tsc`.
2. Run the Python test suite.
3. Run `vsce package` and verify the generated VSIX.
4. Smoke test activation in VS Code using the packaged VSIX.
5. Publish under the `BlackplaneSystems` marketplace publisher with the matching marketplace token.
