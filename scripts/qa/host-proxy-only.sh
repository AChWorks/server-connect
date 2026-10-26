#!/bin/sh
# CI guest ONLY: real pinned sing-box VLESS loopback and selected HTTP proxy.
# The upstream and HTTP origin are independent from the installed manager.
set -eu
umask 077
manager=/usr/local/bin/server-connect
target=http://127.0.0.1:19180/index.html
upstream=sc-qa-vless.service

positive_probe() {
  via=$1
  result=$("$manager" --json probe --via "$via" --url "$target") || exit 1
  printf '%s\n' "$result" | python3 -c '
import json, sys
o=json.load(sys.stdin)
expected=sys.argv[1]
d=o.get("data") or {}
if o.get("ok") is not True or d.get("path") != expected or \
   d.get("result") != "reachable" or d.get("http_status", d.get("status_code", d.get("code"))) != 200:
    sys.exit("Selected path did not return a real HTTP 200 response")
' "$via"
}
negative_proxy_probe() {
  if result=$("$manager" --json probe --via proxy --url "$target"); then
    echo 'Proxy request unexpectedly succeeded after its selected path failed' >&2
    exit 1
  fi
  printf '%s\n' "$result" | python3 -c '
import json, sys
o=json.load(sys.stdin)
if o.get("ok") is not False or not (o.get("error") or {}).get("code"):
    sys.exit("Failing proxy probe did not report a classified error")
d=o.get("data") or {}
if d.get("result") == "reachable":
    sys.exit("Failed selected path was falsely reported reachable")
'
}
active_ready() {
  systemctl is-active --quiet server-connect.service
  systemctl is-enabled --quiet server-connect.service
  status=$("$manager" --json status) || exit 1
  printf '%s\n' "$status" | python3 -c '
import json,sys
o=json.load(sys.stdin)
d=o.get("data") or {}
if (o.get("ok") is not True or d.get("desired") != "proxy"
    or d.get("observed") != "active" or not d.get("selected")):
    sys.exit("Selected proxy desired/observed state changed")
'
  "$manager" --json ready | python3 -c '
import json, sys
o=json.load(sys.stdin)
if o.get("ok") is not True or (o.get("data") or {}).get("local_listener_ready") is not True:
    sys.exit("Installed manager listener was not ready")
'
}
# This exercises independent proxy-aware consumers, not merely curl.
# A Python parent also launches an actual wget grandchild, approximating
# a panel-managed installer process tree while NOT claiming aaPanel itself
# has opted in or that arbitrary binaries honor HTTP proxy variables.
selected_wget() {
  "$manager" exec -- /usr/bin/wget -q -T 6 -t 1 -O - "$target"
}

selected_python_parent() {
  # Separate outage cases are essential: a failed urllib fetch must not
  # short-circuit the independently required wget child-process assertion.
  "$manager" exec -- /usr/bin/python3 -I -B -c '
import subprocess, sys, urllib.error, urllib.request
mode, url = sys.argv[1:]
if mode in ("positive", "urllib-down"):
    try:
        with urllib.request.urlopen(url, timeout=6) as response:
            if response.status != 200 or response.read().strip() != b"SC_QA_WEB_OK":
                sys.exit(12)
    except urllib.error.URLError:
        if mode != "urllib-down":
            raise
        print("SC_QA_PYTHON_URLLIB_PROXY_DOWN")
        sys.exit(0)
    if mode == "urllib-down":
        sys.exit("Python urllib silently reached Direct")
if mode in ("positive", "child-down"):
    try:
        child = subprocess.run(
            ["/usr/bin/wget", "-q", "-T", "6", "-t", "1", "-O", "-", url],
            capture_output=True, timeout=9, check=False)
    except subprocess.TimeoutExpired:
        sys.exit(14)
    if mode == "child-down":
        if child.returncode == 0 or b"SC_QA_WEB_OK" in child.stdout:
            sys.exit("Python-spawned wget reached the independent Direct origin")
        print("SC_QA_PYTHON_WGET_CHILD_PROXY_DOWN")
        sys.exit(0)
    if child.returncode != 0 or child.stdout.strip() != b"SC_QA_WEB_OK":
        sys.exit(13)
if mode != "positive":
    sys.exit(2)
print("SC_QA_PYTHON_SUBPROCESS_SELECTED")
' "$1" "$target"
}

selected_git() {
  "$manager" exec -- /usr/bin/git -c http.lowSpeedTime=6 -c http.lowSpeedLimit=1 \
    ls-remote --exit-code http://127.0.0.1:19180/sc-qa-git.git HEAD
}

selected_apps_positive() {
  wget_positive=$(selected_wget) || {
    echo 'Selected wget failed despite active upstream' >&2; return 1
  }
  [ "$wget_positive" = SC_QA_WEB_OK ] || {
    echo 'Selected wget did not return the independent origin marker' >&2; return 1
  }
  python_positive=$(selected_python_parent positive) || {
    echo 'Selected Python urllib and spawned wget failed despite active upstream' >&2; return 1
  }
  [ "$python_positive" = SC_QA_PYTHON_SUBPROCESS_SELECTED ] || {
    echo 'Selected Python parent did not confirm both consumers' >&2; return 1
  }
  expected=$(/usr/bin/git --git-dir=/root/qa-web/sc-qa-git.git rev-parse HEAD)
  actual=$(selected_git)
  test "$(printf '%s\n' "$actual" | cut -f1)" = "$expected"
  test "$(printf '%s\n' "$actual" | cut -f2)" = HEAD
  echo 'INSTALLED_SELECTED_NONCURL_APPS=PASS (wget, Python urllib->wget, Git HTTP)'
}

selected_apps_negative() {
  # A client silently using Direct while the VLESS upstream is down would
  # succeed against the guest-local origin; such a false pass is forbidden.
  if wget_negative=$(selected_wget 2>/dev/null); then
    echo 'Wget silently reached Direct after selected VLESS failure' >&2; return 1
  fi
  case "$wget_negative" in
    *SC_QA_WEB_OK*)
      echo 'Wget leaked Direct origin data despite reporting an error' >&2; return 1 ;;
  esac
  # The urllib request and spawned wget MUST be invoked separately while
  # the upstream is down. Running the normal positive sequence alone would
  # exit on urllib failure before ever reaching its child.
  python_negative=$(selected_python_parent urllib-down) || {
    echo 'Python urllib outage probe failed without a classified proxy failure' >&2; return 1
  }
  if [ "$python_negative" != SC_QA_PYTHON_URLLIB_PROXY_DOWN ]; then
    echo 'Python urllib silently reached Direct after VLESS failure' >&2; return 1
  fi
  echo 'INSTALLED_SELECTED_PYTHON_URLLIB_FAIL_CLOSED=PASS'
  child_negative=$(selected_python_parent child-down) || {
    echo 'Python-spawned wget outage probe did not complete' >&2; return 1
  }
  if [ "$child_negative" != SC_QA_PYTHON_WGET_CHILD_PROXY_DOWN ]; then
    echo 'Python-spawned wget silently reached Direct after VLESS failure' >&2; return 1
  fi
  echo 'INSTALLED_SELECTED_PYTHON_WGET_CHILD_FAIL_CLOSED=PASS'
  if git_negative=$(selected_git 2>/dev/null); then
    echo 'Git silently reached Direct after selected VLESS failure' >&2; return 1
  fi
  if [ -n "$git_negative" ]; then
    echo 'Git emitted origin refs despite selected VLESS failure' >&2; return 1
  fi
  echo 'INSTALLED_SELECTED_NONCURL_FAIL_CLOSED=PASS'
}

positive() {
  systemctl is-active --quiet "$upstream"
  active_ready
  positive_probe direct
  positive_probe proxy
  # This is an actual opted-in application request; no proxy-env fallback.
  response=$("$manager" exec -- curl -q --fail --silent --show-error \
    --max-time 8 "$target") || exit 1
  [ "$response" = SC_QA_WEB_OK ] || exit 1
  selected_apps_positive
  test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
}
case "$1" in
  setup)
    [ "$#" -eq 1 ]
    test "$(ps -p 1 -o comm=)" = systemd
    # The parent harness already checks the guest-only route and snapshots
    # every route/rule/link across installs; no duplicate rendering-sensitive
    # iproute2 text assertion is needed here.
    [ -x /root/server-connect/bin/sing-box ]
    cat > /root/sc-qa-vless.json <<'CONF'
{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"qa-inbound","listen":"127.0.0.1","listen_port":19182,"users":[{"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}
CONF
    chmod 0600 /root/sc-qa-vless.json
    # A separate native systemd service tests the guest's *credential
    # transport*, independent of Server Connect. Static disposable values only.
    # A system-scope D-Bus broker is absent in this guest; avoid --wait/--pipe.
    test_guest_credential() {
      label=$1
      property=$2
      unit="sc-qa-cred-$label.service"
      systemd-run --quiet --unit="sc-qa-cred-$label" \
        --property=DynamicUser=yes --property="$property" \
        /bin/sh -c 'test "$(cat "$CREDENTIALS_DIRECTORY/sc-qa")" = SC_QA_CREDENTIAL_TEST_ONLY' || return 1
      for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        state=$(systemctl show "$unit" --property=ActiveState --value) || return 1
        result=$(systemctl show "$unit" --property=Result --value) || return 1
        if [ "$state" = inactive ] && [ "$result" = success ]; then
          echo "ISOLATED_CREDENTIAL_$label=PASS"
          return 0
        fi
        if [ "$result" != success ]; then break; fi
        sleep 0.1
      done
      echo "ISOLATED_CREDENTIAL_$label=FAIL ($state/$result)" >&2
      journalctl --no-pager --output=cat -n 10 -u "$unit" >&2 || true
      return 1
    }
    credential_issue=no
    test_guest_credential set "SetCredential=sc-qa:SC_QA_CREDENTIAL_TEST_ONLY" ||
      credential_issue=yes
    printf SC_QA_CREDENTIAL_TEST_ONLY > /root/sc-qa-credential-source
    chmod 0600 /root/sc-qa-credential-source
    test_guest_credential load "LoadCredential=sc-qa:/root/sc-qa-credential-source" ||
      credential_issue=yes
    rm -f /root/sc-qa-credential-source
    if [ "$credential_issue" != no ]; then
      echo 'ISOLATED_CREDENTIAL_TRANSPORT=FAIL (guest capability, not product verification)' >&2
      exit 1
    fi
    /root/server-connect/bin/sing-box check -c /root/sc-qa-vless.json
    # Transient systemd-run units are garbage-collected after stop; this
    # disposable guest needs a restartable QA-owned unit for failure tests.
    cat > /run/systemd/system/sc-qa-vless.service <<'UNIT'
[Unit]
Description=Isolated test-only VLESS upstream

[Service]
Type=simple
ExecStart=/root/server-connect/bin/sing-box run -c /root/sc-qa-vless.json
Restart=no
UNIT
    chmod 0644 /run/systemd/system/sc-qa-vless.service
    systemctl daemon-reload
    systemctl start sc-qa-vless.service
    # This is a fixed, non-sensitive QA-only profile with no reachable foreign peer.
    printf '%s\n' 'vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@127.0.0.1:19182?type=tcp&security=none#CI-Guest' |
      "$manager" --json import --file - > /root/sc-qa-import.json
    selected=$(python3 -c '
import json
o=json.load(open("/root/sc-qa-import.json"))
if o.get("ok") is not True:
    raise SystemExit("QA profile import failed")
print(o["data"]["id"])
')
    "$manager" select "$selected" >/dev/null
    if ! "$manager" connect >/dev/null; then
      # Only local disposable dummy-profile services appear in these logs.
      # Never emit runtime.json, password files or imported URLs.
      echo 'ISOLATED_VLESS_CONNECT=FAIL (guest service diagnostics)' >&2
      systemctl show server-connect.service sc-qa-vless.service         --property=Id,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,LoadCredential,DynamicUser,FragmentPath         --no-pager >&2 || true
      journalctl --no-pager --output=cat -n 35         -u server-connect.service -u sc-qa-vless.service >&2 || true
      exit 1
    fi
    positive
    echo 'INSTALLED_VLESS_PROXY_ONLY=PASS (real selected loopback VLESS + Direct)'
    ;;
  positive)
    [ "$#" -eq 1 ]
    positive
    ;;
  upstream-failure)
    # Repeat the same full negative VLESS/apt checks after both update paths.
    case "$#" in
      1) apt_phase=upstream-stopped ;;
      2) case "$2" in
           upstream-after-upgrade|upstream-after-rollback) apt_phase=$2 ;;
           *) exit 2 ;;
         esac ;;
      *) exit 2 ;;
    esac
    positive
    systemctl stop "$upstream"
    if systemctl is-active --quiet "$upstream"; then exit 1; fi
    positive_probe direct
    negative_proxy_probe
    # An explicitly proxied curl must also fail rather than return Direct.
    if "$manager" exec -- curl -q --fail --silent --show-error \
      --max-time 4 "$target" >/dev/null 2>&1; then
      echo 'Opted-in application leaked to Direct when VLESS upstream stopped' >&2
      exit 1
    fi
    selected_apps_negative
    /bin/sh /root/qa-apt-only.sh negative "$apt_phase"
    active_ready
    systemctl start "$upstream"
    positive
    echo 'INSTALLED_UPSTREAM_FAIL_CLOSED=PASS'
    ;;
  core-failure)
    [ "$#" -eq 1 ]
    positive
    systemctl stop server-connect.service
    if systemctl is-active --quiet server-connect.service; then exit 1; fi
    positive_probe direct
    negative_proxy_probe
    /bin/sh /root/qa-apt-only.sh negative core-stopped
    systemctl start server-connect.service
    positive
    echo 'INSTALLED_CORE_STOP_ISOLATED=PASS'
    ;;
  disconnect)
    [ "$#" -eq 1 ]
    "$manager" disconnect >/dev/null
    if systemctl is-active --quiet server-connect.service ||
       systemctl is-enabled --quiet server-connect.service; then
      echo 'Owned proxy was not stopped/disabled on disconnect' >&2
      exit 1
    fi
    positive_probe direct
    negative_proxy_probe
    test ! -e /var/lib/server-connect/runtime.json
    test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
    echo 'INSTALLED_DISCONNECT_DIRECT=PASS'
    ;;
  *)
    echo 'Usage: host-proxy-only.sh setup|positive|upstream-failure|core-failure|disconnect' >&2
    exit 2
    ;;
esac
