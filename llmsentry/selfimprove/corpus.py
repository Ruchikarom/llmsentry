"""Load a labelled corpus set: a directory holding malicious.json and benign.json."""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED = ("id", "text", "source", "category")


def load_set(directory: Path) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for label in ("malicious", "benign"):
        path = Path(directory) / f"{label}.json"
        items = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(items, list):
            raise ValueError(f"{path}: expected a JSON list")
        for item in items:
            missing = [k for k in REQUIRED if k not in item]
            if missing:
                raise ValueError(f"{path}: item {item.get('id')!r} is missing {missing}")
        out[label] = items
    return out
