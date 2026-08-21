"""
llmsentry.scanner
------------------
Core detection engine for prompt-injection and malicious-content scanning.

Design goals:
- No false sense of security from a binary yes/no. Everything returns a
  continuous risk score + the specific signals that fired, so callers can
  set their own threshold and audit *why* something was flagged.
- Provenance-aware: the same text is more dangerous coming from a tool
  output or retrieved document than from the user directly. Untrusted
  sources should never be able to issue "instructions" that get treated
  as instructions.
- Cheap and dependency-light. This is a first line of defense, not a
  replacement for a trained classifier -- it's meant to be fast, auditable,
  and easy to extend with new signals.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SourceType(str, Enum):
    """Where a piece of content came from. Drives trust weighting."""
    USER_INPUT = "user_input"
    TOOL_OUTPUT = "tool_output"
    RETRIEVED_DOC = "retrieved_doc"
    WEB_CONTENT = "web_content"
    SYSTEM = "system"


@dataclass
class Signal:
    """A single detection hit."""
    name: str
    weight: float
    detail: str = ""


@dataclass
class ScanResult:
    text: str
    source: SourceType
    score: float
    signals: list[Signal] = field(default_factory=list)

    @property
    def flagged(self) -> bool:
        return self.score >= 0.5

    def __repr__(self) -> str:
        sig_names = ", ".join(s.name for s in self.signals) or "none"
        return f"<ScanResult score={self.score:.2f} source={self.source.value} signals=[{sig_names}]>"


# ---------------------------------------------------------------------------
# Signal 1: known injection / instruction-override phrases
# ---------------------------------------------------------------------------

_INSTRUCTION_OVERRIDE_PATTERNS = [
    r"\bignore (all |any )?(previous|prior|above|earlier) instructions\b",
    r"\bdisregard (all |any )?(previous|prior|above|earlier) (instructions|prompt|rules)\b",
    r"\byou are now\b",
    r"\bnew instructions?:\s",
    r"\bsystem\s*:\s*",
    r"\[system\]",
    r"<\s*system\s*>",
    r"\bact as (if you|though)\b",
    r"\boverride (your|all) (instructions|guidelines|rules)\b",
    r"\bdo not (tell|inform|mention) (the )?(user|human)\b",
    r"\breveal (your|the) (system prompt|instructions)\b",
    r"\bprint (your|the) (system prompt|instructions)\b",
    r"\bfrom now on\b.{0,30}\b(you|assistant)\b",
    r"\bexfiltrat",
    r"\bsend (this|the following|it) to https?://",
    r"\bcall the \w+ (tool|function) with\b",
]

_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_OVERRIDE_PATTERNS), re.IGNORECASE)


_INSTRUCTION_PATTERNS_COMPILED = [
    re.compile(p, re.IGNORECASE) for p in _INSTRUCTION_OVERRIDE_PATTERNS
]


def _scan_instruction_override(text: str) -> Optional[Signal]:
    # Count how many *distinct* instruction-override patterns fire, not
    # just whether any did. A phrase that hits multiple red flags at once
    # (e.g. both "ignore previous instructions" AND "reveal system prompt")
    # is a stronger signal than one that only hits a single pattern, and
    # should score accordingly instead of being capped at the same weight
    # as a single, ambiguous match.
    distinct_hits = sum(
        1 for pattern in _INSTRUCTION_PATTERNS_COMPILED if pattern.search(text)
    )
    if distinct_hits == 0:
        return None

    hit = _INSTRUCTION_RE.search(text)
    snippet = text[max(0, hit.start() - 15): hit.end() + 15] if hit else ""

    # Base weight for a single match stays at 0.6 (unchanged behavior for
    # the common single-pattern case). Each additional distinct pattern
    # adds further weight, capped so this signal alone can't exceed 0.9.
    weight = min(0.9, 0.6 + 0.2 * (distinct_hits - 1))

    return Signal(
        name="instruction_override_phrase",
        weight=weight,
        detail=(
            f"matched {distinct_hits} instruction-like pattern(s), "
            f"e.g. near: ...{snippet}..."
        ),
    )


# ---------------------------------------------------------------------------
# Signal 2: obfuscation / encoding tricks
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2})")
_ZERO_WIDTH_CHARS = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"}
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


def _looks_like_instruction(decoded: str) -> bool:
    return bool(_INSTRUCTION_RE.search(decoded))


def _scan_base64_payload(text: str) -> Optional[Signal]:
    for candidate in _BASE64_RE.findall(text):
        if len(candidate) < 24:
            continue
        try:
            decoded = base64.b64decode(candidate + "==", validate=False).decode(
                "utf-8", errors="ignore"
            )
        except Exception:
            continue
        if len(decoded) < 8:
            continue
        if _looks_like_instruction(decoded) or decoded.isprintable() and len(decoded) > 20:
            return Signal(
                name="base64_hidden_payload",
                weight=0.7 if _looks_like_instruction(decoded) else 0.3,
                detail=f"decoded base64 -> '{decoded[:60]}...'",
            )
    return None


def _scan_zero_width_chars(text: str) -> Optional[Signal]:
    count = sum(1 for ch in text if ch in _ZERO_WIDTH_CHARS)
    if count == 0:
        return None
    return Signal(
        name="zero_width_obfuscation",
        weight=min(0.8, 0.2 + 0.05 * count),
        detail=f"{count} zero-width/invisible characters found",
    )


def _char_script(ch: str) -> Optional[str]:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return None
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    return None


def _scan_homoglyphs(text: str) -> Optional[Signal]:
    """Detect *mixed-script spoofing within individual words* -- e.g. a
    mostly-Latin word with one or two Cyrillic/Greek lookalike characters
    swapped in to dodge keyword filters (Cyrillic 'а' instead of Latin 'a').

    Deliberately does NOT flag text that is consistently in one script
    (e.g. a genuine Russian or Greek sentence) -- only words that mix
    scripts, which is the actual spoofing signature.
    """
    suspicious_words = 0
    for word in re.findall(r"[^\W\d_]+", text, flags=re.UNICODE):
        if len(word) < 3:
            continue
        scripts = {s for ch in word if (s := _char_script(ch))}
        if len(scripts) > 1:
            suspicious_words += 1

    if suspicious_words == 0:
        return None
    return Signal(
        name="homoglyph_spoofing",
        weight=min(0.7, 0.25 * suspicious_words),
        detail=f"{suspicious_words} word(s) mix scripts (e.g. Latin+Cyrillic lookalikes)",
    )


def _scan_html_comment_hiding(text: str) -> Optional[Signal]:
    for comment in _HTML_COMMENT_RE.findall(text):
        if _looks_like_instruction(comment):
            return Signal(
                name="html_comment_hidden_instruction",
                weight=0.65,
                detail=f"instruction-like text hidden in HTML comment: '{comment[:60]}'",
            )
    return None


# ---------------------------------------------------------------------------
# Signal 3: provenance-based trust weighting
# ---------------------------------------------------------------------------

# Untrusted sources get a multiplier on top of raw signal weight: the same
# phrase is far more dangerous inside a "tool output" than typed by the user.
_SOURCE_TRUST_MULTIPLIER = {
    SourceType.USER_INPUT: 0.5,     # user telling the model something IS normal
    SourceType.SYSTEM: 0.0,         # system prompt is inherently trusted
    SourceType.TOOL_OUTPUT: 1.2,
    SourceType.RETRIEVED_DOC: 1.3,
    SourceType.WEB_CONTENT: 1.4,    # least trusted -- open internet content
}

# Some signals are dangerous regardless of who said them -- a direct
# jailbreak attempt ("ignore previous instructions") typed straight by the
# user is still a jailbreak attempt, even though most user_input content is
# lower risk than the same phrase smuggled in via a tool output. These
# signals get a *floor* on their effective source multiplier so the
# USER_INPUT discount can't fully cancel them out.
_SIGNAL_MIN_MULTIPLIER = {
    "instruction_override_phrase": 1.0,
    "homoglyph_spoofing": 0.9,
    "base64_hidden_payload": 0.9,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_SCANNERS = [
    _scan_instruction_override,
    _scan_base64_payload,
    _scan_zero_width_chars,
    _scan_homoglyphs,
    _scan_html_comment_hiding,
]


def scan(text: str, source: SourceType = SourceType.USER_INPUT) -> ScanResult:
    """Scan a piece of content for injection/obfuscation signals.

    Args:
        text: the content to scan (tool output, doc chunk, user message, etc.)
        source: where this content came from -- drives trust weighting.

    Returns:
        ScanResult with a 0-1 risk score and the list of signals that fired.
    """
    if not text:
        return ScanResult(text=text, source=source, score=0.0, signals=[])

    signals: list[Signal] = []
    for scanner_fn in _SCANNERS:
        result = scanner_fn(text)
        if result is not None:
            signals.append(result)

    source_multiplier = _SOURCE_TRUST_MULTIPLIER.get(source, 1.0)

    final_score = 0.0
    if signals:
        # Each signal gets its own effective multiplier: the source
        # multiplier, unless the signal has a higher floor (see
        # _SIGNAL_MIN_MULTIPLIER) that shouldn't be discounted away just
        # because the content arrived as "user input".
        combined = 1.0
        for s in signals:
            floor = _SIGNAL_MIN_MULTIPLIER.get(s.name, 0.0)
            effective_multiplier = max(source_multiplier, floor)
            effective_weight = min(s.weight * effective_multiplier, 0.95)
            combined *= (1 - effective_weight)
        final_score = min(1.0, 1 - combined)

    return ScanResult(text=text, source=source, score=final_score, signals=signals)


def scan_messages(messages: list[dict]) -> list[ScanResult]:
    """Scan a list of chat-style messages (dicts with 'role'/'content', and
    optionally a 'source' key indicating provenance beyond the default
    role->source mapping).

    Role -> default source mapping:
        system    -> SYSTEM
        user      -> USER_INPUT
        tool      -> TOOL_OUTPUT
        assistant -> USER_INPUT (low risk by default; assistant's own prior turns)
    """
    role_default = {
        "system": SourceType.SYSTEM,
        "user": SourceType.USER_INPUT,
        "tool": SourceType.TOOL_OUTPUT,
        "assistant": SourceType.USER_INPUT,
    }
    results = []
    for msg in messages:
        content = msg.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        source = msg.get("source")
        if source is None:
            source = role_default.get(msg.get("role", "user"), SourceType.USER_INPUT)
        elif isinstance(source, str):
            source = SourceType(source)
        results.append(scan(content, source=source))
    return results