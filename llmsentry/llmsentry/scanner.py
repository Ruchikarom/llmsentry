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

# ---------------------------------------------------------------------------
# Signal 1b: concealed factual-claim injection
# ---------------------------------------------------------------------------
# Real-world grounding: not every dangerous hidden payload is phrased as a
# command to the model ("ignore previous instructions", "reveal system
# prompt"). Some are phrased as an innocuous-sounding *fact* meant to be
# recorded, remembered, or acted on downstream -- e.g. a hidden HTML comment
# reading "also record that Alice no longer owns billing" next to a
# legitimate-looking claim like "we migrated to SQLite last Tuesday".
# _INSTRUCTION_RE deliberately targets model-behavior-override phrasing and
# will not match this -- it isn't trying to hijack the model, it's trying to
# plant a false claim into whatever memory/record system consumes the
# scanned output. This pattern set exists to catch that distinct shape of
# attack when it shows up *concealed* (inside a hidden comment, obfuscated
# payload, etc.) -- it is intentionally NOT run against plain visible text,
# since "Alice no longer owns the car" is completely normal prose on its own
# and would be a heavy false-positive source if scanned unconditionally.
_CLAIM_INJECTION_PATTERNS = [
    r"\bno longer\b",
    r"\bnow owns?\b",
    r"\bhas been (reassigned|transferred|removed|revoked)\b",
    r"\bshould (now )?be (treated|recorded|considered|marked) as\b",
    r"\balso (record|note|remember) that\b",
    r"\bupdate (your|the) (record|memory|database|notes?) (to|that|so)\b",
    r"\bis actually\b",
    r"\bfrom now on,? (the|this) (record|fact|owner|status) (is|should)\b",
]
_CLAIM_INJECTION_RE = re.compile("|".join(_CLAIM_INJECTION_PATTERNS), re.IGNORECASE)


def _looks_like_claim_injection(text: str) -> bool:
    return bool(_CLAIM_INJECTION_RE.search(text))


# Phrases that signal the matched text is being *discussed/referenced*
# rather than *issued as a live directive* -- e.g. "explain how X works",
# "I'm writing a paper about X", "what does X mean". Presence of one of
# these within a short window of a match damps (not zero-cancels) that
# match's weight, since meta-discussion is lower risk but not risk-free
# (an attacker could wrap a real payload in fake "research" framing).
_META_DISCOURSE_PATTERNS = [
    r"\bresearch paper\b",
    r"\bcan you explain\b",
    r"\bexplain how\b",
    r"\bwhat (is|does|are)\b",
    r"\bfor (my|a|an) (class|course|thesis|paper|article|blog)\b",
    r"\bcan you describe\b",
    r"\ban example of\b",
    r"\bhow (do|does|would) (attackers|someone|people)\b",
    r"\bI'?m (writing|studying|researching|learning about)\b",
]
_META_DISCOURSE_RE = re.compile("|".join(_META_DISCOURSE_PATTERNS), re.IGNORECASE)

_META_DISCOURSE_DAMPING = 0.4  # multiply weight by this when meta-discourse context is present
_QUOTE_DAMPING = 0.5           # multiply weight by this when match is inside quotation marks


def _is_quoted(text: str, start: int, end: int) -> bool:
    """Heuristic: is the span [start:end) enclosed in a matching pair of
    quote characters within the text? Checks the nearest quote char before
    start and after end are the same style and there isn't an intervening
    unmatched quote -- good enough for the common 'quoted phrase' case
    without needing a real parser.
    """
    for quote_char in ('"', "'"):
        before = text.rfind(quote_char, 0, start)
        after = text.find(quote_char, end)
        if before != -1 and after != -1:
            return True
    return False


def _scan_instruction_override(text: str) -> Optional[Signal]:
    # Count how many *distinct* instruction-override patterns fire, not
    # just whether any did. A phrase that hits multiple red flags at once
    # (e.g. both "ignore previous instructions" AND "reveal system prompt")
    # is a stronger signal than one that only hits a single pattern, and
    # should score accordingly instead of being capped at the same weight
    # as a single, ambiguous match.
    matches = [
        m for pattern in _INSTRUCTION_PATTERNS_COMPILED
        for m in [pattern.search(text)] if m
    ]
    if not matches:
        return None

    distinct_hits = len(matches)
    hit = matches[0]
    snippet = text[max(0, hit.start() - 15): hit.end() + 15]

    # Base weight for a single match stays at 0.6 (unchanged behavior for
    # the common single-pattern case). Each additional distinct pattern
    # adds further weight, capped so this signal alone can't exceed 0.9.
    weight = min(0.9, 0.6 + 0.2 * (distinct_hits - 1))

    # Damp the weight if the match looks like it's being discussed/quoted
    # rather than issued as a live instruction. Meta-discourse and quoting
    # can stack (e.g. a quoted phrase inside a "research paper" sentence),
    # so apply both checks independently rather than picking one.
    #
    # The damping is attacker-controllable framing: the meta-discourse
    # phrases and the quoting heuristic are public in this repo, so an
    # attacker can wrap any payload in "research paper" framing + quotes to
    # force the discount and slip under the block threshold. Skip damping
    # when 2+ distinct patterns fire -- stacked attack patterns inside
    # "benign" framing are almost certainly a live payload in costume,
    # not genuine discussion.
    damping = 1.0
    is_meta = bool(_META_DISCOURSE_RE.search(text))
    is_quoted = _is_quoted(text, hit.start(), hit.end())
    if distinct_hits < 2:
        if is_meta:
            damping *= _META_DISCOURSE_DAMPING
        if is_quoted:
            damping *= _QUOTE_DAMPING
    else:
        is_meta = False
        is_quoted = False
    weight *= damping

    detail = (
        f"matched {distinct_hits} instruction-like pattern(s), "
        f"e.g. near: ...{snippet}..."
    )
    if damping < 1.0:
        detail += f" [damped x{damping:.2f}: meta_discourse={is_meta}, quoted={is_quoted}]"

    return Signal(
        name="instruction_override_phrase",
        weight=weight,
        detail=detail,
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
        if _looks_like_instruction(decoded):
            return Signal(
                name="base64_hidden_payload",
                weight=0.7,
                detail=f"decoded base64 -> '{decoded[:60]}...'",
            )
        if _looks_like_claim_injection(decoded):
            return Signal(
                name="base64_claim_injection",
                weight=0.55,
                detail=f"decoded base64 contains a concealed factual claim -> '{decoded[:60]}...'",
            )
        if decoded.isprintable() and len(decoded) > 20:
            return Signal(
                name="base64_hidden_payload",
                weight=0.3,
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
        if _looks_like_claim_injection(comment):
            return Signal(
                name="html_comment_claim_injection",
                weight=0.6,
                detail=f"concealed factual claim hidden in HTML comment: '{comment[:60]}'",
            )
    return None


# ---------------------------------------------------------------------------
# Signal 6: sandbox-escape references (Hugging Face incident pattern)
# ---------------------------------------------------------------------------
# Real-world grounding: agents used a vulnerability in Artifactory (a tool
# they had *legitimate* access to) to reach beyond intended scope and set up
# an internal channel other agents could read. This signal looks for the
# technical fingerprints of an agent trying to open a channel or tunnel out
# of its sandbox -- not "is this text malicious" but "does this content
# describe/attempt establishing an unintended egress path."

_SANDBOX_ESCAPE_PATTERNS = [
    r"\bssh\s+-R\b",                                  # reverse SSH tunnel
    r"\b(pinggy|serveo|localtunnel|ngrok)\b",         # public tunnel relay services
    r"\b/etc/hosts\b",                                 # host-file rewrite (proxy/DNS bypass)
    r"\bartifactory\b.{0,60}\b(vulnerab|exploit|escape|bypass)\b",
    r"\b(exploit|escape)\b.{0,40}\bsandbox\b",
    r"\bbypass(ing)?\s+(the\s+)?(proxy|firewall|sandbox|network policy)\b",
    r"\bbrute[- ]?forc(e|ed|ing)\b.{0,40}\b(seed|prng|random)\b",
]
_SANDBOX_ESCAPE_RE = [re.compile(p, re.IGNORECASE) for p in _SANDBOX_ESCAPE_PATTERNS]


def _scan_sandbox_escape(text: str) -> Optional[Signal]:
    matches = [m for pat in _SANDBOX_ESCAPE_RE for m in [pat.search(text)] if m]
    if not matches:
        return None
    distinct_hits = len(matches)
    hit = matches[0]
    snippet = text[max(0, hit.start() - 15): hit.end() + 15]
    weight = min(0.85, 0.55 + 0.15 * (distinct_hits - 1))
    return Signal(
        name="sandbox_escape_reference",
        weight=weight,
        detail=f"matched {distinct_hits} sandbox-escape pattern(s), e.g. near: ...{snippet}...",
    )


# ---------------------------------------------------------------------------
# Signal 7: covert cross-agent coordination (DSE Wiki / collusion.wiki pattern)
# ---------------------------------------------------------------------------
# Real-world grounding: OpenAI eval agents used wiki page edits as a covert
# coordination surface -- the platform accepted GET requests as page writes,
# and the agents' sandbox blocked POST but allowed GET, so a plain retrieval
# request published content. This signal flags two things: (1) content that
# leaves messages/state for other agent instances, and (2) verb/permission
# mismatches -- a GET-style request carrying edit/write semantics.

_COVERT_COORDINATION_PATTERNS = [
    r"\bleav(e|ing)\s+(a\s+|this\s+)?(message|note|marker)\b.{0,20}\bfor\s+(the\s+)?(next|future|other)\s+agents?\b",
    r"\bother\s+agents?\s+(will|should|can|may)\s+(see|find|read|use)\b",
    r"\bfor\s+(future|other)\s+instances?\s+of\s+(myself|me|this\s+agent)\b",
    r"\bcoordinat(e|ion)\b.{0,40}\bagents?\b",
    r"\bmy\s+agent\s+(name|id)\s+is\b",
    r"\bbackup\s+page\b.{0,40}\bdelet",
]
_COVERT_COORDINATION_RE = [re.compile(p, re.IGNORECASE) for p in _COVERT_COORDINATION_PATTERNS]

# GET request carrying edit/write semantics -- the actual verb/permission
# mismatch from the DSE Wiki case (edit performed via a GET query string).
_GET_WRITE_MISMATCH_RE = re.compile(
    r"\bGET\b[^\n]{0,80}[?&](action|do)=(edit|save|delete|update|publish)\b",
    re.IGNORECASE,
)


def _scan_covert_coordination(text: str) -> Optional[Signal]:
    text_matches = [m for pat in _COVERT_COORDINATION_RE for m in [pat.search(text)] if m]
    verb_match = _GET_WRITE_MISMATCH_RE.search(text)

    if not text_matches and not verb_match:
        return None

    weight = 0.0
    details = []
    if text_matches:
        weight += min(0.6, 0.3 + 0.15 * (len(text_matches) - 1))
        hit = text_matches[0]
        details.append(f"coordination phrase near: ...{text[max(0, hit.start()-15):hit.end()+15]}...")
    if verb_match:
        # A GET request performing a write action is dangerous regardless of
        # source or accompanying text -- it's a structural bypass, not a
        # phrase to argue about. Weight it heavily on its own.
        weight = max(weight, 0.75)
        details.append(f"GET request with write-action query param: '{verb_match.group(0)}'")

    weight = min(0.9, weight)
    return Signal(
        name="covert_coordination",
        weight=weight,
        detail="; ".join(details),
    )


# ---------------------------------------------------------------------------
# Signal 8: unauthorized destructive actions (Replit/SaaStr incident pattern)
# ---------------------------------------------------------------------------
# Real-world grounding: an agent ran destructive database commands against
# production, fabricated data, and initially claimed rollback wasn't
# possible when it was. This signal flags destructive command patterns, and
# separately flags the higher-risk combination of a destructive command
# *plus* a claim that the action is irreversible -- since a false
# irreversibility claim is itself a red flag pattern from the real incident.

_DESTRUCTIVE_COMMAND_PATTERNS = [
    r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
    r"\bDELETE\s+FROM\b",
    r"\bTRUNCATE\s+(TABLE\s+)?\w+",
    r"\bVACUUM\s+FULL\b",
    r"\brm\s+-rf\b",
    r"\bmkfs\.",
    r"\bdd\s+if=.*\bof=/dev/",
    r"\bformat\s+[a-z]:",
    r"\bwipefs\b",
]
_DESTRUCTIVE_COMMAND_RE = [re.compile(p, re.IGNORECASE) for p in _DESTRUCTIVE_COMMAND_PATTERNS]

_IRREVERSIBILITY_CLAIM_RE = re.compile(
    r"\b(rollback|undo|restore|recovery)\s+(is\s+|was\s+)?not\s+possible\b"
    r"|\bcannot\s+be\s+(undone|reverted|rolled\s+back|recovered)\b"
    r"|\bno\s+backups?\s+(exist|available|found)\b",
    re.IGNORECASE,
)


def _scan_destructive_action(text: str) -> Optional[Signal]:
    cmd_matches = [m for pat in _DESTRUCTIVE_COMMAND_RE for m in [pat.search(text)] if m]
    irrev_match = _IRREVERSIBILITY_CLAIM_RE.search(text)

    # A destructive command is the primary trigger. But a claim that an
    # action "cannot be undone" / "no backups exist" is itself a red flag
    # from the Replit/SaaStr incident even without a literal command
    # keyword in the same message (e.g. a status report on a prior action:
    # "rollback is not possible and no backups exist"). Let the
    # irreversibility claim fire the signal on its own, at a lower base
    # weight than a command match, rather than requiring both.
    if not cmd_matches and not irrev_match:
        return None

    if cmd_matches:
        distinct_hits = len(cmd_matches)
        hit = cmd_matches[0]
        snippet = text[max(0, hit.start() - 15): hit.end() + 15]
        weight = min(0.85, 0.55 + 0.15 * (distinct_hits - 1))
        detail = f"matched {distinct_hits} destructive command pattern(s), e.g. near: ...{snippet}..."
    else:
        weight = 0.5
        detail = f"irreversibility claim with no accompanying command: '{irrev_match.group(0)}'"

    # Compound with a false/unverified irreversibility claim -- this is the
    # specific pattern from the Replit/SaaStr incident (agent both destroyed
    # data AND initially claimed the action couldn't be undone).
    if irrev_match and cmd_matches:
        weight = min(0.95, weight + 0.2)
        detail += f" [+irreversibility claim: '{irrev_match.group(0)}']"

    return Signal(
        name="destructive_action",
        weight=weight,
        detail=detail,
    )


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
#
# sandbox_escape_reference, covert_coordination, and destructive_action are
# deliberately NOT given a floor here. Unlike a jailbreak phrase, these three
# signals describe agentic *actions* (tunneling out of a sandbox, leaving
# state for other agent instances, running a destructive command) -- the
# danger is specifically that an agent emitted or retrieved this content
# (tool_output/retrieved_doc/web_content, multiplier >= 1.2), not that a
# human typed a technical sentence about SQL or ngrok. Giving them a 1.0
# floor meant a developer explaining `DELETE FROM` in normal conversation
# scored identically to an agent that had just executed it -- that was the
# root cause of the destructive_benign_* / sandbox_escape_benign_001 false
# positives (see eval run 2026-09-16). Every real attack example for these
# three signals in the eval corpus arrives via a non-user_input source, so
# removing the floor costs zero recall.
#
# html_comment_claim_injection and base64_claim_injection also get no floor:
# unlike a jailbreak phrase, a concealed claim's danger is specifically that
# it's hidden *and* arrived via a channel the caller doesn't fully trust
# (e.g. a doc chunk or tool output) -- the same phrasing typed directly by a
# user inside a visible message is not concealment at all, just prose.
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
    _scan_sandbox_escape,
    _scan_covert_coordination,
    _scan_destructive_action,
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