"""Proposers return a reply text for (system, user).

GeminiProposer calls the Gemini generateContent API and reads GEMINI_API_KEY.
AnthropicProposer calls the Anthropic Messages API and reads ANTHROPIC_API_KEY.
OpenAICompatProposer calls an OpenAI-compatible chat-completions API
(OpenRouter is wired in) and reads the key named by its caller.
FallbackProposer tries several proposers in order. Overloads, rate limits and
network errors are retried with backoff before it moves on.
StubProposer replays canned replies and makes no network calls; the tests and
dry runs use it.

Keys stay in the environment and are never written anywhere.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Statuses that mean "not now": overload, rate limit, gateway trouble.
TRANSIENT_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
MAX_WAIT = 120.0  # seconds: caps both the backoff and a server's Retry-After


class ProviderError(RuntimeError):
    """A provider gave no usable answer. transient=True: a later try may succeed."""

    def __init__(self, message: str, *, transient: bool, retry_after: float | None = None):
        super().__init__(message)
        self.transient = transient
        self.retry_after = retry_after


def _retry_after(value: str | None) -> float | None:
    try:
        return min(float(value), MAX_WAIT) if value else None
    except ValueError:  # an HTTP date, say: fall back to our own backoff
        return None


def _post_json(url: str, headers: dict[str, str], payload: dict, timeout: int, label: str) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"content-type": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise ProviderError(f"{label} HTTP {exc.code}: {detail}",
                            transient=exc.code in TRANSIENT_STATUS,
                            retry_after=_retry_after(exc.headers.get("Retry-After"))) from None
    except (OSError, ValueError) as exc:  # no connection, a timeout, or a body that is not JSON
        raise ProviderError(f"{label} unreachable or unreadable: {exc}", transient=True) from None


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
        data = _post_json(API_URL, {"x-api-key": self._key, "anthropic-version": "2023-06-01"},
                          {"model": self.model, "max_tokens": self.max_tokens, "system": system,
                           "messages": [{"role": "user", "content": user}]},
                          self.timeout, label="Anthropic API")
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
        payload = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {"maxOutputTokens": self.max_tokens},
        }
        data = _post_json(GEMINI_URL.format(model=self.model), {"x-goog-api-key": self._key},
                          payload, self.timeout, label="Gemini API")
        return gemini_text(data)


def gemini_text(data: dict) -> str:
    """The reply's visible text. Raises ProviderError if there is none."""
    candidates = data.get("candidates") or []
    if not candidates:
        reason = (data.get("promptFeedback") or {}).get("blockReason")
        if reason:  # a safety block on this prompt: the same prompt will be blocked again
            raise ProviderError(f"Gemini blocked the request ({reason})", transient=False)
        raise ProviderError("Gemini returned no candidates", transient=True)
    first = candidates[0]
    parts = (first.get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
    if not text:
        raise ProviderError(f"Gemini returned no text (finish reason: {first.get('finishReason', 'unknown')})",
                            transient=True)
    return text


class OpenAICompatProposer:
    """Any OpenAI-compatible chat-completions API. The key goes in an Authorization header."""

    def __init__(self, provider: str, url: str, key_env: str, model: str,
                 max_tokens: int = 8192, timeout: int = 300):
        self.provider = provider
        self.url = url
        self.model = model
        self.name = f"{provider}:{model}"
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._key = os.environ.get(key_env, "")
        if not self._key:
            raise RuntimeError(f"Set {key_env} in your environment. It is never written to the repo.")

    def propose(self, system: str, user: str) -> str:
        payload = {"model": self.model, "max_tokens": self.max_tokens,
                   "messages": [{"role": "system", "content": system},
                                {"role": "user", "content": user}]}
        data = _post_json(self.url, {"authorization": f"Bearer {self._key}"}, payload,
                          self.timeout, label=f"{self.provider} API")
        try:
            text = data["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError):
            text = ""
        if not text.strip():
            raise ProviderError(f"{self.provider} returned no text", transient=True)
        return text


class FallbackProposer:
    """Tries each proposer in order.

    A transient failure is retried on the same proposer with doubling waits (or
    the server's Retry-After), up to `retries` extra attempts. A refusal moves on
    at once. `name` is the proposer that answered the last call. If none answers,
    it raises ProviderError: transient=False only when every failure was a
    refusal, which a later round would not fix.
    """

    def __init__(self, proposers, *, retries: int = 4, base_delay: float = 10.0,
                 log=print, sleep=time.sleep):
        if not proposers:
            raise ValueError("FallbackProposer needs at least one proposer")
        self.proposers = list(proposers)
        self.retries = retries
        self.base_delay = base_delay
        self.name = self.proposers[0].name
        self._log = log
        self._sleep = sleep

    def propose(self, system: str, user: str) -> str:
        failures: list[str] = []
        transient = False
        for proposer in self.proposers:
            for attempt in range(self.retries + 1):
                try:
                    text = proposer.propose(system, user)
                except ProviderError as exc:
                    failures.append(f"{proposer.name}: {exc}")
                    retryable, hint = exc.transient, exc.retry_after
                except Exception as exc:  # not a ProviderError: count it, keep the run going
                    failures.append(f"{proposer.name}: {type(exc).__name__}: {exc}")
                    retryable, hint = True, None
                else:
                    self.name = proposer.name
                    return text
                transient = transient or retryable
                if not retryable or attempt == self.retries:
                    break  # this proposer is out for this round: try the next one
                wait = hint or min(self.base_delay * 2 ** attempt, MAX_WAIT)
                self._log(f"{proposer.name} gave no answer ({failures[-1]}); retrying in {wait:.0f}s")
                self._sleep(wait)
        raise ProviderError("no provider answered: " + " | ".join(failures), transient=transient)


class StubProposer:
    """Replays canned replies in order; returns "" once they run out."""

    name = "stub"

    def __init__(self, replies: list[str]):
        self._replies = list(replies)
        self.prompts: list[str] = []

    def propose(self, system: str, user: str) -> str:
        self.prompts.append(user)
        return self._replies.pop(0) if self._replies else ""
