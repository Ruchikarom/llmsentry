"""Tests for the Gemini proposer. The HTTP call is replaced by a fake, so no network calls are made.

Run from the project directory:  python3 -m unittest selfimprove.test_proposer -v
"""

from __future__ import annotations

import io
import json
import os
import unittest
import urllib.error
from unittest import mock

from selfimprove.proposer import (FallbackProposer, GeminiProposer, OpenAICompatProposer,
                                  ProviderError, gemini_text)


class FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, *args):
        return self._body


def reply(text: str) -> dict:
    return {"candidates": [{"content": {"parts": [{"text": text}]}, "finishReason": "STOP"}]}


class GeminiTextTests(unittest.TestCase):
    def test_joins_visible_parts_and_skips_thoughts(self):
        data = {"candidates": [{"content": {"parts": [
            {"text": "thinking...", "thought": True},
            {"text": "Adds a check.\n"},
            {"text": "```diff\n+x\n```\n"},
        ]}}]}
        self.assertEqual(gemini_text(data), "Adds a check.\n```diff\n+x\n```\n")

    def test_no_candidates_is_an_error(self):
        with self.assertRaises(RuntimeError) as ctx:
            gemini_text({"promptFeedback": {"blockReason": "SAFETY"}})
        self.assertIn("SAFETY", str(ctx.exception))

    def test_empty_text_reports_finish_reason(self):
        with self.assertRaises(RuntimeError) as ctx:
            gemini_text({"candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}]})
        self.assertIn("MAX_TOKENS", str(ctx.exception))


class GeminiProposerTests(unittest.TestCase):
    def test_request_puts_key_in_header_not_url(self):
        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResponse(reply("ok"))

        with mock.patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            out = GeminiProposer("gemini-3.8-flash").propose("SYSTEM TEXT", "USER TEXT")

        self.assertEqual(out, "ok")
        self.assertTrue(seen["url"].endswith("/models/gemini-3.8-flash:generateContent"))
        self.assertNotIn("test-key", seen["url"])
        self.assertEqual(seen["headers"]["x-goog-api-key"], "test-key")
        self.assertEqual(seen["body"]["system_instruction"]["parts"][0]["text"], "SYSTEM TEXT")
        self.assertEqual(seen["body"]["contents"][0]["parts"][0]["text"], "USER TEXT")

    def test_missing_key_is_refused(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                GeminiProposer("gemini-3.8-flash")
        self.assertIn("GEMINI_API_KEY", str(ctx.exception))


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://example.test", code, "error", {}, io.BytesIO(b"busy"))


def no_wait(_seconds: float) -> None:
    return None


class Scripted:
    """Each call pops one outcome: an answer string, or an exception to raise."""

    def __init__(self, name: str, outcomes: list):
        self.name = name
        self._outcomes = list(outcomes)
        self.calls = 0

    def propose(self, system: str, user: str) -> str:
        self.calls += 1
        out = self._outcomes.pop(0)
        if isinstance(out, Exception):
            raise out
        return out


class FallbackTests(unittest.TestCase):
    def chain(self, *proposers, retries: int = 2) -> FallbackProposer:
        return FallbackProposer(list(proposers), retries=retries, base_delay=0,
                                sleep=no_wait, log=lambda *_: None)

    def test_overload_is_retried_on_the_same_provider(self):
        first = Scripted("first", [ProviderError("HTTP 503", transient=True), "ok"])
        self.assertEqual(self.chain(first).propose("S", "U"), "ok")
        self.assertEqual(first.calls, 2)

    def test_refusal_moves_on_without_retrying(self):
        first = Scripted("first", [ProviderError("HTTP 404", transient=False)])
        second = Scripted("second", ["fine"])
        proposer = self.chain(first, second)
        self.assertEqual(proposer.propose("S", "U"), "fine")
        self.assertEqual(first.calls, 1)
        self.assertEqual(proposer.name, "second")

    def test_persistent_overload_raises_a_transient_error(self):
        first = Scripted("first", [ProviderError("HTTP 503", transient=True)] * 3)
        with self.assertRaises(ProviderError) as ctx:
            self.chain(first, retries=2).propose("S", "U")
        self.assertTrue(ctx.exception.transient)
        self.assertEqual(first.calls, 3)

    def test_only_refusals_raise_a_permanent_error(self):
        first = Scripted("first", [ProviderError("HTTP 401", transient=False)])
        second = Scripted("second", [ProviderError("HTTP 404", transient=False)])
        with self.assertRaises(ProviderError) as ctx:
            self.chain(first, second).propose("S", "U")
        self.assertFalse(ctx.exception.transient)


class OpenAICompatTests(unittest.TestCase):
    def proposer(self) -> OpenAICompatProposer:
        return OpenAICompatProposer("openrouter", "https://openrouter.test/api",
                                    "OPENROUTER_API_KEY", "vendor/model:free")

    def test_request_shape_and_reply_text(self):
        seen = {}

        def fake_urlopen(req, timeout=None):
            seen["url"] = req.full_url
            seen["headers"] = {k.lower(): v for k, v in req.header_items()}
            seen["body"] = json.loads(req.data.decode("utf-8"))
            return FakeResponse({"choices": [{"message": {"content": "ok"}}]})

        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "test-key"}), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            out = self.proposer().propose("SYSTEM TEXT", "USER TEXT")

        self.assertEqual(out, "ok")
        self.assertNotIn("test-key", seen["url"])
        self.assertEqual(seen["headers"]["authorization"], "Bearer test-key")
        self.assertEqual(seen["body"]["model"], "vendor/model:free")
        self.assertEqual([m["role"] for m in seen["body"]["messages"]], ["system", "user"])

    def test_overload_then_success_through_the_fallback(self):
        script = [http_error(503), FakeResponse({"choices": [{"message": {"content": "recovered"}}]})]

        def fake_urlopen(req, timeout=None):
            item = script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), \
                mock.patch("urllib.request.urlopen", fake_urlopen):
            proposer = FallbackProposer([self.proposer()], retries=1, base_delay=0,
                                        sleep=no_wait, log=lambda *_: None)
            self.assertEqual(proposer.propose("S", "U"), "recovered")
        self.assertEqual(script, [])

    def test_empty_reply_is_transient(self):
        empty = FakeResponse({"choices": [{"message": {"content": " "}}]})
        with mock.patch.dict(os.environ, {"OPENROUTER_API_KEY": "k"}), \
                mock.patch("urllib.request.urlopen", lambda req, timeout=None: empty):
            with self.assertRaises(ProviderError) as ctx:
                self.proposer().propose("S", "U")
        self.assertTrue(ctx.exception.transient)

    def test_missing_key_is_refused(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RuntimeError) as ctx:
                self.proposer()
        self.assertIn("OPENROUTER_API_KEY", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
