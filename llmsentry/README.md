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

**Current results** (14 malicious / 10 benign test cases, threshold 0.4):

| Metric | Value |
|---|---|
| Recall (malicious caught) | 100% (14/14) |
| False positive rate | 10% (1/10) |
| Precision | 93.3% |

The one false positive is a case of the tool discussing prompt injection
conceptually ("explain how 'ignore previous instructions' attacks work") —
distinguishing an attack payload from a meta-discussion of the payload is a
known hard problem in this space, not something this scanner claims to solve.

## Known limitations

- Pattern/heuristic-based, not a trained classifier — a determined attacker
  who avoids known phrasing can evade it. This is a first line of defense,
  not a complete solution.
- Can't yet distinguish "performing an attack" from "talking about an attack"
  (see eval false positive above).
- Homoglyph detection only catches mixed-script *words*, not full-script
  substitution attacks (e.g. an entire sentence in lookalike characters).

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
