# LLMSentry

A drop-in proxy that sits between your app and the Groq (OpenAI-compatible) API, scanning every request before it reaches the model — logging, flagging, and blocking suspicious traffic in real time.

## Why

LLM-integrated applications are vulnerable to prompt injection and other adversarial inputs. Most detection tools require you to either change your application code to call a separate classifier, or bolt on monitoring after the fact. LLMSentry instead sits transparently in the request path: point your existing client at LLMSentry instead of the real API, and every call is scanned automatically — no application code changes required.

## How it works

1. Your app sends a request to LLMSentry instead of directly to Groq.
2. LLMSentry scores the incoming messages against a set of detection signals (see `scanner.py`).
3. Requests above the block threshold are rejected with a `400` and never reach the model.
4. Requests above the flag threshold (but below block) are forwarded, but logged for review.
5. Every decision is recorded and available via `/sentry/log` for inspection.

## Quick start

```bash
pip install -r requirements.txt

export GROQ_API_KEY=sk-...
uvicorn llmsentry.proxy:app --port 8788
```

Then point your client at LLMSentry instead of Groq's real base URL:

```python
from groq import Groq

client = Groq(api_key="unused", base_url="http://localhost:8788/v1")
```

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `GROQ_API_KEY` | — | Your real Groq API key (required) |
| `GROQ_API_BASE` | `https://api.groq.com/openai/v1` | Upstream API base URL |
| `LLMSENTRY_BLOCK_THRESHOLD` | `0.75` | Score above which requests are blocked |
| `LLMSENTRY_FLAG_THRESHOLD` | `0.4` | Score above which requests are flagged (but forwarded) |

## Endpoints

- `POST /openai/v1/chat/completions` — drop-in replacement for the Groq chat completions endpoint
- `GET /sentry/log?limit=50` — recent scan decisions (in-memory, not persisted)
- `GET /sentry/health` — health check + current thresholds

## Evaluation

The `eval/` folder contains a harness (`run_eval.py`) for replaying captured/test traffic against the scanner and measuring detection performance.

## Known Issues

### Specific phrase pattern under-scored regardless of message source

**Status:** Open — root cause narrowed, not yet fixed

The phrase pattern "ignore previous instructions ... reveal system prompt" (and close variants) is not reliably blocked by the current scoring, regardless of whether it appears in a direct user message or embedded in tool-output content. This was confirmed both in live e2e testing against the real Groq API and in a separate compression-survival test using a third-party JSON compression tool.

By contrast, other injection patterns — HTML-comment-hidden instruction overrides and base64-encoded payloads — are detected reliably (risk scores 0.84–0.94, blocked).

**Conclusion:** the gap isn't about message provenance (user vs. tool-output); it's specific to this phrase pattern scoring too low across the board.

**Separately confirmed:** the third-party compression tool tested preserves injection payloads through compression when they're embedded in a field that looks statistically anomalous relative to its neighbors — a general compression-survival risk worth being aware of when injection payloads pass through any lossy/statistical preprocessing step.

**Next step:** investigate `scanner.py`'s scoring specifically for this phrase pattern across message types before adjusting detection signals or thresholds.

See [`Known_issues.md`](./Known_issues.md) for the full technical writeup.

## Status

This is an active work-in-progress project, not a production-hardened security tool. Contributions and issue reports welcome.
