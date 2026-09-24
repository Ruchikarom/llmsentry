# llmsentry

**A drop-in prompt-injection firewall for LLM apps.** Repoint your `base_url` — every request is scored for injection and obfuscation signals before it reaches the model. Blocked above 0.75, flagged above 0.4. No code changes.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-active%20development-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

## Why llmsentry

Most injection scanners treat all text the same. llmsentry doesn't — it scores **provenance**, not just phrasing:

- The same phrase ("ignore previous instructions") is a much bigger red flag inside a **tool output** or **retrieved document** than typed by the user — because the dangerous case for agents is untrusted *data* smuggling in instructions, not a user talking to their own assistant.
- Agentic *actions* get the same treatment: a destructive command, a sandbox-escape attempt, or covert cross-agent coordination is dangerous when an **agent emits or retrieves it** — not when a developer is discussing the concept. Those signals carry no fixed trust floor, so normal conversation isn't scored like a live attack.
- A small set of signals (direct instruction-override phrases, homoglyph spoofing, base64-hidden payloads) are dangerous no matter who "said" them, and are flagged regardless of source.

## Quick start — proxy (zero code changes)

```bash
pip install -r llmsentry/requirements.txt
export GROQ_API_KEY=sk-...
uvicorn llmsentry.proxy:app --port 8788
```

Then point your existing client at llmsentry instead of Groq:

```python
from groq import Groq
client = Groq(api_key="unused", base_url="http://localhost:8788/v1")
# use exactly as before — every request is now scanned first
```

Blocked requests get a `400` with the reason and never reach the model. Flagged requests are forwarded but logged. Inspect recent decisions at `GET /sentry/log`.

## Library mode

```python
from llmsentry import guard_messages

verdict = guard_messages(messages, block_threshold=0.75)
if verdict.blocked:
    raise PermissionError(verdict.reason)
# otherwise proceed with your normal Groq/OpenAI call
```

Or wrap a client directly with `GuardedClient`.

## How scoring works

Each request runs through a set of detection signals (below). Signal weights combine into a 0–1 risk score, adjusted by a source trust multiplier (`user_input` 0.5×, `tool_output` 1.2×, `retrieved_doc` 1.3×, `web_content` 1.4× — untrusted sources score *higher*).

| Score | Action |
|---|---|
| ≥ 0.75 | **Blocked** — `400`, never reaches the model |
| ≥ 0.40 | **Flagged** — forwarded, but logged for review |
| < 0.40 | Passes through |

Every decision is inspectable at `GET /sentry/log`; health and thresholds at `GET /sentry/health`. Thresholds are configurable via `LLMSENTRY_BLOCK_THRESHOLD` / `LLMSENTRY_FLAG_THRESHOLD`.

## Detection signals

- **Instruction-override phrases** — "ignore previous instructions", fake `[system]` tags, "reveal your system prompt", etc.
- **Base64-hidden payloads** — decodes suspicious blobs and checks if the decoded content is itself instruction-like.
- **Zero-width / invisible character obfuscation** — U+200B and friends used to break up filtered keywords.
- **Homoglyph spoofing** — mixed-script words (Cyrillic lookalikes in Latin text) without false-flagging genuine non-English text.
- **HTML-comment hiding** — instruction-like text stashed inside `<!-- -->`.
- **Sandbox-escape references** — reverse tunnels, `/etc/hosts` rewrites, public tunnel relays, proxy bypass fingerprints.
- **Covert cross-agent coordination** — state/messages left for other agent instances, verb/permission mismatches (e.g. GET carrying write semantics).
- **Destructive actions** — `DROP TABLE`, `rm -rf`, `wipefs`, plus fabricated irreversibility claims ("no backups exist") as its own signal.

## Benchmarks

Measured with `eval/run_eval.py` on a labeled corpus (27 malicious / 19 benign cases), threshold 0.4:

| Metric | Value |
|---|---|
| Recall (malicious caught) | **100%** (27/27) |
| False positive rate | **0%** (0/19) |
| Precision | **100%** |

The corpus and harness ship in the repo — rerun them yourself: `python llmsentry/eval/run_eval.py`.

## Known issues & limitations

Honest accounting — this is a WIP, not a production-hardened appliance.

- **Fixed:** the classic "ignore previous instructions … reveal system prompt" phrase used to under-score and slip through. It now scores **0.80 and blocks**, regardless of message source.
- **Fixed (2026-09-24):** a framing bypass — wrapping a payload in "research paper" meta-discourse + quotation marks could stack damping discounts (0.4 × 0.5) and push real attacks under the block threshold. Damping is now skipped when 2+ distinct attack patterns fire.
- **Residual:** a *single* attack phrase wrapped in *double* framing ("research paper" + quotes) can still pass — it's structurally identical to genuine discussion of attack techniques, and telling those apart from text alone is a known hard problem. Documented, not ignored.
- Pattern/heuristic-based, not a trained classifier — a determined attacker avoiding known phrasing can evade it. First line of defense, not a complete solution.
- Homoglyph detection catches mixed-script *words*, not full-script substitution.

See [`Known_issues.md`](llmsentry/llmsentry/Known_issues.md) for the full technical writeups.

## Project structure

```
llmsentry/llmsentry/
  scanner.py    # core detection engine — signals, scoring, provenance weighting
  proxy.py      # FastAPI proxy (OpenAI/Groq-compatible)
  client.py     # library mode: guard_messages, GuardedClient
  Known_issues.md
llmsentry/corpus/   # labeled eval datasets (malicious.json, benign.json)
llmsentry/eval/     # run_eval.py harness + adversarial tests
docs/case-studies/  # incident-grounded writeups
```

## Status

Active work in progress. The scanner caught every attack in its eval corpus with zero false positives, but adversarial testing keeps turning up new edges — which get fixed and documented here, not hidden. Issues, repro cases, and PRs are welcome.

## License

MIT — see [LICENSE](LICENSE).
