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
positive() {
  systemctl is-active --quiet "$upstream"
  active_ready
  positive_probe direct
  positive_probe proxy
  # This is an actual opted-in application request; no proxy-env fallback.
  response=$("$manager" exec -- curl -q --fail --silent --show-error \
    --max-time 8 "$target") || exit 1
  [ "$response" = SC_QA_WEB_OK ] || exit 1
  test "$(cat /var/lib/server-connect/profiles/qa-retained)" = SC_QA_RETAIN_PROFILE_BYTES
}
case "$1" in
  setup)
    [ "$#" -eq 1 ]
    test "$(ps -p 1 -o comm=)" = systemd
    test -z "$(ip -4 route show default)" && test -z "$(ip -6 route show default)"
    [ -x /root/server-connect/bin/sing-box ]
    cat > /root/sc-qa-vless.json <<'CONF'
{"log":{"level":"warn"},"inbounds":[{"type":"vless","tag":"qa-inbound","listen":"127.0.0.1","listen_port":19182,"users":[{"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"}]}],"outbounds":[{"type":"direct","tag":"direct"}]}
CONF
    chmod 0600 /root/sc-qa-vless.json
    /root/server-connect/bin/sing-box check -c /root/sc-qa-vless.json
    systemd-run --quiet --unit=sc-qa-vless --property=Restart=no \
      /root/server-connect/bin/sing-box run -c /root/sc-qa-vless.json
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
    [ "$#" -eq 1 ]
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
