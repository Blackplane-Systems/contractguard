import json
import os
import subprocess
import sys
from pathlib import Path


def test_bridge_scan_outputs_json():
    repo_root = Path(__file__).resolve().parent.parent
    target = repo_root / "samples" / "regex"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "contractguard.bridge",
            "scan",
            "--path",
            str(target),
            "--analyzer",
            "regex",
            "--rules-dir",
            str(repo_root / "rules"),
        ],
        cwd=repo_root,
        env={**os.environ, "PYTHONPATH": str(repo_root / "src")},
        capture_output=True,
        text=True,
        check=True,
    )

    payload = json.loads(result.stdout)
    assert payload["analyzer"] == "regex"
    assert "findings" in payload
