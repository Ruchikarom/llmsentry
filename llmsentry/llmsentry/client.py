"""
llmsentry.client
------------------
Library-mode usage: wrap a chat-completion call (Groq, OpenAI-compatible,
etc.) so every message is scanned before it reaches the model.

Two ways to use it:

1. Function wrapper:
    from llmsentry.client import guard_messages

    messages = [...]
    verdict = guard_messages(messages, block_threshold=0.7)
    if verdict.blocked:
        raise ValueError(verdict.reason)
    # otherwise call your LLM as normal with `messages`

2. GuardedClient wraps a Groq-style client and intercepts .chat.completions.create
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .scanner import ScanResult, scan_messages


@dataclass
class Verdict:
    results: list[ScanResult]
    block_threshold: float
    flag_threshold: float

    @property
    def max_score(self) -> float:
        return max((r.score for r in self.results), default=0.0)

    @property
    def blocked(self) -> bool:
        return self.max_score >= self.block_threshold

    @property
    def flagged(self) -> bool:
        return self.max_score >= self.flag_threshold

    @property
    def reason(self) -> str:
        if not self.blocked and not self.flagged:
            return "clean"
        worst = max(self.results, key=lambda r: r.score)
        sig_names = ", ".join(s.name for s in worst.signals)
        return (
            f"risk={worst.score:.2f} source={worst.source.value} "
            f"signals=[{sig_names}]"
        )


def guard_messages(
    messages: list[dict],
    block_threshold: float = 0.75,
    flag_threshold: float = 0.4,
) -> Verdict:
    """Scan a list of chat messages and return a Verdict.

    Does not mutate or call anything -- pure scan + decision. Caller decides
    what to do with a blocked/flagged verdict (raise, redact, log, etc.).
    """
    results = scan_messages(messages)
    return Verdict(results=results, block_threshold=block_threshold, flag_threshold=flag_threshold)


class GuardedClient:
    """Wraps any OpenAI/Groq-compatible client so chat completions are
    scanned before being sent. Raises PermissionError if blocked by default;
    pass on_block to customize (e.g. redact instead of raise).
    """

    def __init__(
        self,
        client,
        block_threshold: float = 0.75,
        flag_threshold: float = 0.4,
        on_block: Optional[Callable[[Verdict], None]] = None,
        on_flag: Optional[Callable[[Verdict], None]] = None,
    ):
        self._client = client
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self._on_block = on_block
        self._on_flag = on_flag

    def chat_completions_create(self, *, messages: list[dict], **kwargs):
        verdict = guard_messages(
            messages, block_threshold=self.block_threshold, flag_threshold=self.flag_threshold
        )
        if verdict.blocked:
            if self._on_block:
                self._on_block(verdict)
                return None
            raise PermissionError(f"llmsentry blocked request: {verdict.reason}")
        if verdict.flagged and self._on_flag:
            self._on_flag(verdict)

        return self._client.chat.completions.create(messages=messages, **kwargs)
