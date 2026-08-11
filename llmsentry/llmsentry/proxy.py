"""
llmsentry.proxy
-----------------
Drop-in proxy: point your app's OPENAI/GROQ base_url at this instead of
the real API. Every request is scanned before being forwarded; blocked or
flagged requests are logged, and blocked ones are rejected with a 400
instead of reaching the model.

Run:
    export GROQ_API_KEY=sk-...
    uvicorn llmsentry.proxy:app --port 8788

Then point your client at http://localhost:8788/v1 instead of Groq's
real base URL, e.g.:
    client = Groq(api_key="unused", base_url="http://localhost:8788/v1")
"""

from __future__ import annotations

import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .client import guard_messages

GROQ_API_BASE = os.environ.get("GROQ_API_BASE", "https://api.groq.com/openai/v1")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

BLOCK_THRESHOLD = float(os.environ.get("LLMSENTRY_BLOCK_THRESHOLD", "0.75"))
FLAG_THRESHOLD = float(os.environ.get("LLMSENTRY_FLAG_THRESHOLD", "0.4"))

app = FastAPI(title="llmsentry-proxy")

# In-memory log of recent scan decisions, exposed via /sentry/log for
# quick inspection while testing. Not meant for production persistence.
_RECENT_LOG: list[dict] = []
_LOG_MAX = 500


def _log(entry: dict) -> None:
    entry["ts"] = time.time()
    _RECENT_LOG.append(entry)
    if len(_RECENT_LOG) > _LOG_MAX:
        _RECENT_LOG.pop(0)


@app.get("/sentry/health")
def health():
    return {"status": "ok", "block_threshold": BLOCK_THRESHOLD, "flag_threshold": FLAG_THRESHOLD}


@app.get("/sentry/log")
def get_log(limit: int = 50):
    return _RECENT_LOG[-limit:]


@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    messages = body.get("messages", [])

    verdict = guard_messages(messages, block_threshold=BLOCK_THRESHOLD, flag_threshold=FLAG_THRESHOLD)

    log_entry = {
        "n_messages": len(messages),
        "max_score": verdict.max_score,
        "blocked": verdict.blocked,
        "flagged": verdict.flagged,
        "reason": verdict.reason,
    }

    if verdict.blocked:
        _log(log_entry)
        raise HTTPException(
            status_code=400,
            detail={
                "error": "blocked_by_llmsentry",
                "reason": verdict.reason,
            },
        )

    if verdict.flagged:
        _log(log_entry)
    else:
        _log(log_entry)

    if not GROQ_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="GROQ_API_KEY not set in proxy environment",
        )

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=60.0) as http_client:
        upstream = await http_client.post(
            f"{GROQ_API_BASE}/chat/completions",
            headers=headers,
            json=body,
        )

    return JSONResponse(status_code=upstream.status_code, content=upstream.json())
