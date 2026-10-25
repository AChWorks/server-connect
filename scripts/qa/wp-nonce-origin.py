#!/usr/bin/env python3
"""Disposable disconnected guest: independent nonce-echo HTTP origin (127.0.0.1)."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
import re


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urlsplit(self.path)
        values = parse_qs(url.query)
        nonce = values.get("value", [""])[0]
        if url.path != "/nonce" or not re.fullmatch(r"[0-9a-f]{16}", nonce):
            self.send_error(400)
            return
        body = ("SC_QA_WP_NONCE:" + nonce).encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


HTTPServer(("127.0.0.1", 19185), Handler).serve_forever()
