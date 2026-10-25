#!/usr/bin/env python3
"""Disposable guest ONLY: adapt supported manager exec credentials to WP Proxy."""
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlsplit

DEST = Path("/var/lib/sc-qa-wp/proxy-prepend.php")
PROXY_ENV = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")


def render(environ):
    urls = [environ.get(name, "") for name in PROXY_ENV]
    if not urls[0] or any(value != urls[0] for value in urls):
        raise ValueError("Inconsistent manager-selected proxy environment")
    if environ.get("NO_PROXY", "") or environ.get("no_proxy", ""):
        raise ValueError("Unexpected manager proxy bypass")
    parsed = urlsplit(urls[0])
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Unsupported selected proxy port") from exc
    password = parsed.password or ""
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or port != 20807
        or parsed.username != "sc"
        or not re.fullmatch(r"[0-9a-f]{48}", password)
        or parsed.path or parsed.query or parsed.fragment
    ):
        raise ValueError("Unsupported manager-selected HTTP proxy identity")
    # Every interpolated field is fixed or regexp-bounded ASCII. The dynamic
    # password remains local to a root-created private PHP config, never stdout.
    return (
        "<?php\n"
        "// Disposable QA-only PHP-FPM pool settings, not an application edit.\n"
        "define('WP_PROXY_HOST', '127.0.0.1');\n"
        "define('WP_PROXY_PORT', 20807);\n"
        "define('WP_PROXY_USERNAME', 'sc');\n"
        "define('WP_PROXY_PASSWORD', '" + password + "');\n"
        "define('WP_PROXY_BYPASS_HOSTS', 'localhost');\n"
    )


def main():
    if sys.argv != [sys.argv[0]] or os.geteuid() != 0:
        raise SystemExit("QA private WordPress credential bridge requires guest root")
    try:
        content = render(os.environ)
    except ValueError as exc:
        raise SystemExit("QA private WordPress credential bridge rejected: " + str(exc))
    # The parent directory is created exclusively by the disposable harness.
    # Its absolute identity is fixed here rather than supplied by a caller.
    try:
        st = DEST.parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
            raise ValueError("QA WordPress private directory not root-owned")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(DEST, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            DEST.unlink(missing_ok=True)
            raise
    except (OSError, ValueError):
        raise SystemExit("QA private WordPress credential file creation failed")
    # Never echo a proxy URI, username/password, config or request target.
    print("WORDPRESS_PRIVATE_PROXY_CREDENTIAL_BRIDGE=PASS")


if __name__ == "__main__":
    main()
