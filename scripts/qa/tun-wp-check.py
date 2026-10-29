#!/usr/bin/env python3
"""Strict genuine FastCGI and WordPress status for isolated transparent TUN QA."""
import json
import re
import sys

MAX_BYTES = 16384


def validate(raw: bytes, mode: str, expected_source: str) -> None:
    if mode not in ("positive", "negative") or expected_source not in (
        "10.254.72.1", "8.8.8.8", "none"
    ) or (mode == "negative") != (expected_source == "none"):
        raise ValueError("invalid QA expectation")
    if len(raw) > MAX_BYTES:
        raise ValueError("FastCGI response exceeds size limit")
    headers, separator, payload = raw.partition(b"\r\n\r\n")
    if not separator:
        headers, separator, payload = raw.partition(b"\n\n")
    if not separator:
        raise ValueError("missing FastCGI header boundary")
    http_status = 200
    seen_status = False
    json_type = False
    for header in headers.replace(b"\r", b"").split(b"\n"):
        if b":" not in header:
            raise ValueError("malformed FastCGI header")
        name, value = header.split(b":", 1)
        if name.lower() == b"status":
            if seen_status or not re.fullmatch(rb"\s*[1-5][0-9]{2}(?:\s+[^\r\n]*)?", value):
                raise ValueError("invalid HTTP status")
            http_status = int(value.strip().split(b" ", 1)[0])
            seen_status = True
        if name.lower() == b"content-type":
            if json_type or not re.fullmatch(rb"\s*application/json\s*", value, re.I):
                raise ValueError("wrong Content-Type")
            json_type = True
    if not json_type:
        raise ValueError("missing JSON Content-Type")
    try:
        state = json.loads(payload.strip())
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid JSON response") from exc
    if not isinstance(state, dict) or state.get("php_sapi") != "fpm-fcgi" or state.get("wp_installed") is not True:
        raise ValueError("not a genuine installed WordPress FPM response")
    if state.get("proxy_enabled") is not False or state.get("proxy_selected") is not False:
        raise ValueError("WordPress enabled application proxy; not transparent TUN")
    if mode == "positive":
        if (http_status != 200 or state.get("origin_http_code") != 200 or
                state.get("origin_source") != expected_source or
                state.get("nonce_match") is not True or state.get("wp_error_code") != ""):
            raise ValueError("WordPress selected-path proof missing or wrong source")
    elif (http_status != 502 or state.get("origin_http_code") != 0 or
          state.get("origin_source") != "" or state.get("nonce_match") is not False or
          state.get("wp_error_code") != "http_request_failed"):
        raise ValueError("WordPress upstream failure was not a transport failure")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Usage: tun-wp-check.py positive|negative SOURCE")
    try:
        validate(sys.stdin.buffer.read(MAX_BYTES + 1), sys.argv[1], sys.argv[2])
    except ValueError as exc:
        raise SystemExit(f"REAL_TUN_WORDPRESS=FAIL ({exc})")
    print(f"REAL_TUN_WORDPRESS_FPM=PASS ({sys.argv[1]}, source={sys.argv[2]})")
