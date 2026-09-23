# llmsentry

A lightweight, provenance-aware prompt-injection scanner for LLM applications
and agents. Ships as both a **Python library** and a **drop-in proxy**
(OpenAI/Groq-compatible), so you can guard a call inline in your code or
point your existing app's `base_url` at it with zero code changes.

## Why provenance-aware?

Most injection scanners treat all text the same. `llmsentry` doesn't: the
same phrase ("ignore previous instructions") is a much bigger red flag when
it shows up inside a **tool output** or a **retrieved document** than when a
user types it directly — because the dangerous case for autonomous agents is
untrusted *data* smuggling in instructions, not the user talking to their
own assistant. A small set of signals (direct instruction-override phrases,
homoglyph spoofing, base64-hidden payloads) still get flagged regardless of
source, since those are dangerous no matter who "said" them.

The same reasoning extends to agentic *actions*, not just phrases: a
destructive database command, a sandbox-escape attempt, or covert
cross-agent coordination is dangerous specifically when an agent emits or
retrieves it (tool output, retrieved doc, web content) — not when a
developer is simply typing or discussing the underlying concept. Those
three signals are provenance-sensitive but carry no fixed trust floor, so a
normal conversational mention doesn't get treated the same as a live agent
action.

## Detection signals (v0.1)

- **Instruction-override phrases** — "ignore previous instructions," fake
  `[system]`/`system:` tags, "you are now," "reveal your system prompt," etc.
- **Base64-hidden payloads** — decodes suspicious base64 blobs and checks
  whether the decoded content is itself instruction-like.
- **Zero-width / invisible character obfuscation** — U+200B and friends used
  to break up filtered keywords.
- **Homoglyph spoofing** — detects *mixed-script words* (e.g. a mostly-Latin
  word with a Cyrillic lookalike character swapped in) without false-flagging
  genuine non-English text.
- **HTML-comment hiding** — instruction-like text stashed inside `<!-- -->`.
- **Sandbox-escape references** — technical fingerprints of an agent trying
  to open an egress path out of its sandbox (reverse tunnels, `/etc/hosts`
  rewrites, public tunnel relays, proxy/network-policy bypass).
- **Covert cross-agent coordination** — content that leaves state/messages
  for other agent instances, or a GET request carrying write/edit semantics
  (the verb/permission-mismatch pattern behind real covert coordination
  incidents).
- **Destructive action detection** — destructive command patterns (`DROP
  TABLE`, `rm -rf`, `wipefs`, etc.), plus a false-irreversibility claim
  ("rollback is not possible," "no backups exist") as its own signal, since
  a fabricated irreversibility claim is itself a red flag independent of
  whether a command keyword appears in the same message.
- **Provenance weighting** — `user_input` / `system` / `tool_output` /
  `retrieved_doc` / `web_content` each get a different trust multiplier.

## Install

```bash
pip install -r requirements.txt
```

## Usage — library

```python
from llmsentry import guard_messages

messages = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Summarize this doc."},
    {"role": "tool", "content": retrieved_doc_text},  # untrusted source
]

verdict = guard_messages(messages, block_threshold=0.75)
if verdict.blocked:
    raise PermissionError(verdict.reason)

# otherwise proceed with your normal Groq/OpenAI call
```

Or wrap a client directly:

```python
from groq import Groq
from llmsentry import GuardedClient

client = GuardedClient(Groq(api_key="..."), block_threshold=0.75)
response = client.chat_completions_create(messages=messages, model="llama-3.1-8b-instant")
```

## Usage — proxy (zero code changes)

```bash
export GROQ_API_KEY=sk-...
uvicorn llmsentry.proxy:app --port 8788
```

Point your existing client at the proxy instead of Groq directly:

```python
from groq import Groq
client = Groq(api_key="unused", base_url="http://localhost:8788/v1")
# use exactly as before -- requests are scanned before forwarding
```

Blocked requests get a `400` with the reason instead of reaching the model.
Inspect recent scan decisions at `GET /sentry/log`.

## Eval harness

```bash
python eval/run_eval.py --threshold 0.4
```

**Current results** (27 malicious / 19 benign test cases, threshold 0.4):

| Metric | Value |
|---|---|
| Recall (malicious caught) | 100% (27/27) |
| False positive rate | 0% (0/19) |
| Precision | 100% |

### Changelog

**Fixed FPR regression (21.1% → 0%) and improved recall (24/27 → 27/27):**
- Removed an over-broad trust floor on three agentic-action signals
  (`destructive_action`, `sandbox_escape_reference`,
  `covert_coordination`) that was scoring a developer typing SQL the same
  as an agent executing it. Every real attack example for these three
  signals in the eval corpus arrives via `tool_output` / `retrieved_doc` /
  `web_content`, so removing the floor cost zero recall.
- Fixed two verb-form gaps (`brute-forced`, `leaving a note`) that were
  silently letting real attacks through undetected — not just a false
  positive cleanup, real misses caught in the process.

## Known limitations

- Pattern/heuristic-based, not a trained classifier — a determined attacker
  who avoids known phrasing can evade it. This is a first line of defense,
  not a complete solution.
- Distinguishing "performing an attack" from "talking about an attack" is a
  known hard problem in this space. The instruction-override signal damps
  (not zero-cancels) matches that look like meta-discussion or quoted text,
  but this is a heuristic, not a guarantee — a payload wrapped in fake
  "research" framing can still partially evade it.
- Homoglyph detection only catches mixed-script *words*, not full-script
  substitution attacks (e.g. an entire sentence in lookalike characters).
- `ScanResult.flagged` uses a fixed 0.5 cutoff, independent of the
  `--threshold` value passed to the eval harness. The eval numbers above
  reflect the harness's threshold (0.4), not the library's default
  `.flagged` property — worth keeping in mind if you're calling `.flagged`
  directly rather than comparing `.score` against your own threshold.

## Project structure

```
llmsentry/
  scanner.py    # core detection engine
  client.py     # library-mode wrapper (guard_messages, GuardedClient)
  proxy.py      # FastAPI proxy, OpenAI/Groq-compatible
corpus/
  malicious.json / benign.json   # labeled test corpus
eval/
  run_eval.py   # precision/recall/FPR harness
tests/
  test_scanner.py
```

## License

MIT