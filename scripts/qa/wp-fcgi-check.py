#!/usr/bin/env python3
"""Fail-closed FastCGI response classifier for the disposable WordPress QA."""
import json
import re
import sys

MAX_BYTES = 16384


def validate(raw: bytes, expected: str) -> None:
    if len(raw) > MAX_BYTES:
        raise ValueError("FastCGI response exceeds bounded output")
    head, sep, payload = raw.partition(b"\r\n\r\n")
    if not sep:
        head, sep, payload = raw.partition(b"\n\n")
    if not sep:
        raise ValueError("FastCGI response has no header boundary")
    headers = head.replace(b"\r", b"").split(b"\n")
    status = 200
    content_type = False
    seen_status = False
    for header in headers:
        if b":" not in header:
            raise ValueError("Malformed FastCGI header")
        name, value = header.split(b":", 1)
        if name.lower() == b"status":
            if seen_status or not re.fullmatch(rb"\s*[1-5][0-9]{2}(?:\s+[^\r\n]*)?", value):
                raise ValueError("Invalid FastCGI Status header")
            status = int(value.strip().split(b" ", 1)[0])
            seen_status = True
        if name.lower() == b"content-type":
            if content_type or not re.fullmatch(rb"\s*application/json\s*", value, re.I):
                raise ValueError("FastCGI did not return JSON Content-Type")
            content_type = True
    if not content_type:
        raise ValueError("FastCGI JSON Content-Type absent")
    try:
        data = json.loads(payload.strip())
    except (UnicodeDecodeError, ValueError) as err:
        raise ValueError("FastCGI body is not JSON") from err
    if not isinstance(data, dict):
        raise ValueError("FastCGI JSON body not an object")
    if data.get("php_sapi") != "fpm-fcgi" or data.get("wp_installed") is not True:
        raise ValueError("Genuine installed WordPress PHP-FPM not verified")
    if data.get("proxy_enabled") is not True or data.get("proxy_selected") is not True:
        raise ValueError("WordPress did not explicitly select the proxy path")
    if data.get("localhost_exempt") is not True:
        raise ValueError("WordPress localhost exemption changed")
    app_status = data.get("status")
    if type(app_status) is not int:
        raise ValueError("WordPress HTTP result lacks numeric status")
    nonce = data.get("nonce_match")
    if expected == "positive":
        if status != 200 or app_status != 200 or nonce is not True:
            raise ValueError("Selected WordPress nonce acquisition failed")
    elif expected == "negative":
        if status != 502 or app_status == 200 or nonce is not False:
            raise ValueError("Unusable selected WordPress path was falsely accepted")
    else:
        raise ValueError("Unsupported FastCGI expectation")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("positive", "negative"):
        raise SystemExit("Usage: wp-fcgi-check.py positive|negative PHASE")
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        validate(raw, sys.argv[1])
    except ValueError as err:
        raise SystemExit(f"WORDPRESS_FPM({sys.argv[2]})=FAIL ({err})")
    print(f"INSTALLED_WORDPRESS_FPM({sys.argv[2]})=PASS ({sys.argv[1]})")
