#!/usr/bin/env python3
"""Exercise the exact QA FastCGI classifier with false-success signatures."""
import importlib.util
import json
from pathlib import Path
import unittest

SOURCE = Path(__file__).with_name("wp-fcgi-check.py")
spec = importlib.util.spec_from_file_location("wp_fcgicheck", SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def response(*, negative=False, **overrides):
    obj = {
        "php_sapi": "fpm-fcgi",
        "wp_installed": True,
        "proxy_enabled": True,
        "proxy_authenticated": True,
        "proxy_selected": True,
        "localhost_exempt": True,
        "status": 502 if negative else 200,
        "nonce_match": False if negative else True,
    }
    obj.update(overrides)
    status = b"Status: 502 Bad Gateway\r\n" if negative else b""
    return status + b"Content-Type: application/json\r\nCache-Control: no-store\r\n\r\n" + json.dumps(obj).encode()


class FailClosedFixture(unittest.TestCase):
    def test_expected_positive_and_negative(self):
        checker.validate(response(), "positive")
        checker.validate(response(negative=True), "negative")

    def test_invalid_fixtures_rejected(self):
        bad = [
            (b"", "positive"),
            (response()[:24], "positive"),
            (b"Content-Type: application/json\r\n\r\n{}", "positive"),
            (response() + b" " * checker.MAX_BYTES, "positive"),
            (response(php_sapi="cli"), "positive"),
            (response(wp_installed=False), "positive"),
            (response(proxy_enabled=False), "positive"),
            (response(proxy_authenticated=False), "positive"),
            (response(proxy_selected=False), "positive"),
            (response(localhost_exempt=False), "positive"),
            (response(status=0), "positive"),
            (response(nonce_match=False), "positive"),
            (response(), "negative"),  # direct fallback must never pass
            (response(negative=True, status=200), "negative"),
            (response(negative=True, nonce_match=True), "negative"),
            (response(negative=True).replace(b"502 Bad Gateway", b"200 OK"), "negative"),
            (response(negative=True).replace(b"application/json", b"text/plain"), "negative"),
            (response(negative=True).replace(b"Content-Type:", b"X-Other:"), "negative"),
            (response().replace(b"\r\n\r\n", b"\r\n"), "positive"),
        ]
        for raw, expectation in bad:
            with self.subTest(expectation=expectation, raw=raw[:90]):
                with self.assertRaises(ValueError):
                    checker.validate(raw, expectation)


if __name__ == "__main__":
    unittest.main()
