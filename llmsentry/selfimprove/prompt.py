"""Prompt text for the proposer.

Example texts are shown JSON-escaped, so zero-width and lookalike characters
are visible to the model. The held-out set never reaches this module.
"""

from __future__ import annotations

import json

SYSTEM = """You improve a rule-based prompt-injection scanner.

You get the full source of llmsentry/llmsentry/scanner.py, a list of attack examples the scanner misses, and a list of benign examples it wrongly flags.

Propose exactly one small, general change to scanner.py that catches the missed attacks without flagging the benign examples.

Rules:
1. Only edit scanner.py. A diff that touches any other file is rejected.
2. Write general patterns. Never paste example texts into the code.
3. Do not change the block or flag thresholds, the source trust multipliers, or the tests.
4. Keep behaviour for everything else. The unit tests must still pass.
5. Reply with one sentence of rationale, then exactly one ```diff block: a unified diff with the headers `--- a/llmsentry/llmsentry/scanner.py` and `+++ b/llmsentry/llmsentry/scanner.py`, and enough context lines to apply cleanly."""


def describe(item: dict) -> str:
    line = (f"- {item['id']} | category={item['category']} | source={item['source']}"
            f" | score={item['score']:.2f} | signals={item['signals'] or 'none'}")
    if item.get("error"):
        line += f" | ERROR={item['error']}"
    return f"{line}\n  text={json.dumps(item['text'], ensure_ascii=True)}"


def build_user_prompt(scanner_src: str, misses: list[dict], fps: list[dict],
                      history: list[str]) -> str:
    parts = ["## Current scanner.py", "```python", scanner_src.rstrip("\n"), "```", "",
             "## Attacks the scanner misses (fix these)"]
    parts += [describe(i) for i in misses] or ["(none)"]
    parts += ["", "## Benign examples the scanner wrongly flags (stop flagging these)"]
    parts += [describe(i) for i in fps] or ["(none)"]
    if history:
        parts += ["", "## Earlier attempts that were rejected (do not repeat them)"]
        parts += [f"- {h}" for h in history[-3:]]
    return "\n".join(parts)
