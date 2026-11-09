"""Proposers return a reply text for (system, user). Three implementations.

AnthropicProposer calls the Anthropic Messages API and reads ANTHROPIC_API_KEY.
GeminiProposer calls the Gemini generateContent API and reads GEMINI_API_KEY.
Both keep their key in the environment and never write it anywhere.
StubProposer replays canned replies and makes no network calls; the tests and
dry runs use it.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


class AnthropicProposer:
    def __init__(self, model: str, max_tokens: int = 4096, timeout: int = 300):
        self.name = model
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not self._key:
            raise RuntimeError("Set ANTHROPIC_API_KEY in your environment. It is never written to the repo.")

    def propose(self, system: str, user: str) -> str:
        body = json.dumps({"model": self.model, "max_tokens": self.max_tokens,
                           "system": system,
                           "messages": [{"role": "user", "content": user}]}).encode("utf-8")
        req = urllib.request.Request(API_URL, data=body, method="POST", headers={
            "x-api-key": self._key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"Anthropic API HTTP {exc.code}: {detail}") from None
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")


class GeminiProposer:
    """Calls Gemini generateContent. The key goes in a header, never in the URL."""

    def __init__(self, model: str, max_tokens: int = 16384, timeout: int = 300):
        self.name = f"gemini:{model}"
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._key = os.environ.get("GEMINI_API_KEY", "")
        if not self._key:
            raise RuntimeError("Set GEMINI_API_KEY in your environment. It is never written to the repo.")

    def propose(self, system: str, user: str) -> str:
        body = json.dumps({
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": self.max_tokens},
        }).encode("utf-8")
        req = urllib.request.Request(GEMINI_URL.format(model=self.model), data=body, method="POST", headers={
            "x-goog-api-key": self._key,
            "content-type": "application/json",
        })
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.load(resp)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RuntimeError(f"Gemini API HTTP {exc.code}: {detail}") from None
        return gemini_text(data)


def gemini_text(data: dict) -> str:
    """The reply's visible text. Raises if there is none, so the round is logged as an error."""
    candidates = data.get("candidates") or []
    if not candidates:
        reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates returned")
        raise RuntimeError(f"Gemini returned no candidates ({reason})")
    first = candidates[0]
    parts = (first.get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    if not text:
        raise RuntimeError(f"Gemini returned no text (finish reason: {first.get('finishReason', 'unknown')})")
    return text


class StubProposer:
    """Replays canned replies in order; returns "" once they run out."""

    name = "stub"

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.prompts: list[str] = []

    def propose(self, system: str, user: str) -> str:
        self.prompts.append(user)
        return self._replies.pop(0) if self._replies else ""
