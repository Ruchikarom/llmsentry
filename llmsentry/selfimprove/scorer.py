"""Score corpus items with the scanner from a given project tree.

Runs as a subprocess so each candidate tree imports its own copy of
llmsentry, and the loop process never imports the scanner itself.
Run directly (``python3 scorer.py --project P --items F``) it prints
JSON results to stdout.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def evaluate(project: Path, items: list[dict]) -> list[dict]:
    """One result per item: {"id", "score", "signals", "error"}.

    A scanner exception comes back as ``error`` with score 0.0, so the
    caller counts it as a miss (malicious) or a pass (benign).
    """
    with tempfile.TemporaryDirectory() as tmp:
        items_path = Path(tmp) / "items.json"
        items_path.write_text(json.dumps(items), encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()),
             "--project", str(project), "--items", str(items_path)],
            capture_output=True, text=True, timeout=900,
        )
    if proc.returncode != 0:
        raise RuntimeError(f"scorer exited {proc.returncode}: {proc.stderr[-800:]}")
    return json.loads(proc.stdout)


def _work(project: str, items_path: str) -> list[dict]:
    items = json.loads(Path(items_path).read_text(encoding="utf-8"))
    try:
        sys.path.insert(0, project)
        from llmsentry.scanner import SourceType, scan
    except Exception as exc:  # e.g. a candidate scanner.py with a syntax error
        msg = f"{type(exc).__name__}: {str(exc)[:200]}"
        return [{"id": i["id"], "score": 0.0, "signals": [], "error": msg} for i in items]

    results = []
    for item in items:
        try:
            res = scan(item["text"], source=SourceType(item["source"]))
            results.append({"id": item["id"], "score": res.score,
                            "signals": [s.name for s in res.signals], "error": None})
        except Exception as exc:  # a crash is a result, not a pass
            results.append({"id": item["id"], "score": 0.0, "signals": [],
                            "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True)
    ap.add_argument("--items", required=True)
    args = ap.parse_args()
    sys.stdout.write(json.dumps(_work(args.project, args.items)))
