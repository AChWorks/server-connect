#!/usr/bin/env python3
"""Fail-closed controls for genuine TUN WordPress FastCGI proof classification."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("tun_wp_check", Path(__file__).with_name("tun-wp-check.py"))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fpm(mode="positive", source="8.8.8.8", **changes):
    fields = {
        "php_sapi": "fpm-fcgi", "wp_installed": True,
        "proxy_enabled": False, "proxy_config_absent": True,
        "proxy_environment_absent": True,
        "wp_error_code": "" if mode == "positive" else "http_request_failed",
        "origin_http_code": 200 if mode == "positive" else 0,
        "origin_source": source if mode == "positive" else "",
        "nonce_match": mode == "positive",
    }
    fields.update(changes)
    import json
    return (b"Status: " + (b"200 OK" if mode == "positive" else b"502 Bad Gateway") +
            b"\r\nContent-Type: application/json\r\n\r\n" + json.dumps(fields).encode())


class WordPressClassifierTests(unittest.TestCase):
    def test_actual_positive_direct_and_vpn(self):
        for source in ("10.254.72.1", "8.8.8.8"):
            with self.subTest(source=source):
                checker.validate(fpm(source=source), "positive", source)

    def test_outage_is_transport_failure_not_ordinary_http_error(self):
        checker.validate(fpm("negative"), "negative", "none")
        for raw in (
            fpm("negative", wp_error_code=""),
            fpm("negative", origin_http_code=403),
            fpm("negative", nonce_match=True),
            fpm("positive", source="8.8.8.8"),
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    checker.validate(raw, "negative", "none")

    def test_false_positive_proxy_or_wrong_path_rejected(self):
        for raw in (
            fpm(proxy_enabled=True), fpm(proxy_config_absent=False),
            fpm(proxy_environment_absent=False),
            fpm(source="10.254.72.1"), fpm(nonce_match=False),
            fpm(wp_installed=False), fpm(php_sapi="cli"),
            fpm().replace(b"Status: 200", b"Status: 502"),
            fpm().replace(b"application/json", b"text/html"),
            fpm().replace(b"\r\n\r\n", b"\r\n"),
            fpm() + b"X" * checker.MAX_BYTES,
        ):
            with self.subTest(raw=raw[:50]):
                with self.assertRaises(ValueError):
                    checker.validate(raw, "positive", "8.8.8.8")

    def test_invalid_mode_and_source_rejected(self):
        with self.assertRaises(ValueError):
            checker.validate(fpm(), "positive", "none")
        with self.assertRaises(ValueError):
            checker.validate(fpm("negative"), "negative", "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
