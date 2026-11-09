"""Tests for the Gemini proposer. The HTTP call is replaced by a fake, so no network calls are made.

Run from the project directory:  python3 -m unittest selfimprove.test_proposer -v
"""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from selfimprove.proposer import GeminiProposer, gemini_text


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


if __name__ == "__main__":
    unittest.main()
