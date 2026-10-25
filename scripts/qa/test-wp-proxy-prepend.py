#!/usr/bin/env python3
"""Fail-closed unit tests for WordPress QA credential bridge (no secret logs)."""
import importlib.util
from pathlib import Path
import unittest

src = Path(__file__).with_name("wp-proxy-prepend.py")
spec = importlib.util.spec_from_file_location("wp_proxy_prepend_qa", src)
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)

EXAMPLE_SECRET = "0123456789abcdef" * 3
SELECTED = "http://sc:" + EXAMPLE_SECRET + "@127.0.0.1:20807"


def environment():
    return {**{key: SELECTED for key in bridge.PROXY_ENV}, "NO_PROXY": "", "no_proxy": ""}


class CredentialBridgeRegression(unittest.TestCase):
    def test_selected_private_proxy_accepted(self):
        rendered = bridge.render(environment())
        self.assertIn("define('WP_PROXY_HOST', '127.0.0.1');", rendered)
        self.assertIn("define('WP_PROXY_PORT', 20807);", rendered)
        self.assertIn("define('WP_PROXY_USERNAME', 'sc');", rendered)
        self.assertIn("define('WP_PROXY_PASSWORD',", rendered)
        self.assertIn("define('WP_PROXY_BYPASS_HOSTS', 'localhost');", rendered)

    def test_untrusted_proxy_contract_rejected(self):
        cases = [
            {"HTTP_PROXY": ""},
            {"http_proxy": ""},
            {"NO_PROXY": "localhost"},
            {"no_proxy": "*"},
            {"ALL_PROXY": "http://sc:broken@127.0.0.1:20807"},
        ]
        for bad in [
            "http://127.0.0.1:20807",
            "http://sc:weak@127.0.0.1:20807",
            "http://sc:" + EXAMPLE_SECRET + "@example.com:20807",
            "http://sc:" + EXAMPLE_SECRET + "@127.0.0.1:20808",
            "http://admin:" + EXAMPLE_SECRET + "@127.0.0.1:20807",
            "socks5://sc:" + EXAMPLE_SECRET + "@127.0.0.1:20807",
            SELECTED + "/unsafe-path",
            SELECTED + "?bad=yes",
            SELECTED + "#test",
            "http://sc:" + EXAMPLE_SECRET + "@127.0.0.1:invalid",
        ]:
            cases.append({key: bad for key in bridge.PROXY_ENV})
        for change in cases:
            with self.subTest(change=tuple(change.keys())):
                env = environment()
                env.update(change)
                with self.assertRaises(ValueError):
                    bridge.render(env)


if __name__ == "__main__":
    unittest.main()
