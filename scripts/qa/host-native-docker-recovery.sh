#!/bin/sh
# Run only inside the already disposable, disconnected installed-host guest.
# Exercise the real kernel/nft cleanup implementation with the exact
# sing-box 1.14.3 Docker-enabled post-SIGKILL layout seen on IRA-124.
# This is a Core-layout fixture, NOT a real Core SIGKILL or host field proof.
set -eu
# A precondition failure must identify the exact refused guest assumption;
# product routing is never exercised when an isolation or ownership check fails.
refuse() {
  printf 'NATIVE_DOCKER_GUEST_REFUSAL: %s\n' "$1" >&2
  exit 2
}
[ "${SC_QA_NATIVE_DOCKER_GUEST-}" = yes ] || refuse 'missing explicit guest opt-in'
[ "$(id -u)" = 0 ] || refuse 'not guest root'
[ -f /.dockerenv ] || refuse 'not a Docker guest'
[ -d /run/systemd/system ] || refuse 'missing systemd runtime'
[ "$(ps -p 1 -o comm= | tr -d ' ')" = systemd ] || refuse 'PID 1 is not systemd'
[ -x /root/qa-native-recovery-test ] || refuse 'missing executable recovery test binary'
[ "$(systemctl is-active server-connect-native-tun.service || :)" != active ] || refuse 'native TUN service active'
[ "$(systemctl is-active server-connect.service || :)" != active ] || refuse 'proxy service active'
# Only this disconnected QA guest's route text may be logged; the fixture
# must never print a physical host's network configuration or profile data.
actual_default=$(ip -4 route show default) || refuse 'cannot inspect isolated default route'
# iproute2 can render a semantically identical default with trailing blanks;
# normalize ONLY line-end blanks, not route tokens, links or extra routes.
actual_default=$(printf '%s\n' "$actual_default" | sed 's/[[:blank:]]*$//') ||
  refuse 'cannot normalize isolated default route'
[ "$actual_default" = "default dev lo scope link metric 4242" ] ||
  refuse "unexpected isolated default route (observed: ${actual_default:-<none>})"
for name in scouter0 docker0 br-foreign sctun0; do
  if ip link show dev "$name" >/dev/null 2>&1; then
    refuse "unexpected existing interface $name"
  fi
done
if nft list table ip filter >/dev/null 2>&1 || nft list table inet sing-box >/dev/null 2>&1; then
  refuse 'existing fixture nft table'
fi
[ -z "$(ip -4 rule show | grep -E '^1:|^1420[0-9]:|^32768:' || :)" ] || refuse 'preexisting managed IPv4 RPDB priorities'
[ -z "$(ip -6 rule show | grep -E '^1:|^1420[0-9]:|^32768:' || :)" ] || refuse 'preexisting managed IPv6 RPDB priorities'
echo 'NATIVE_DOCKER_GUEST_PRECONDITIONS=PASS'

scratch=$(mktemp -d /run/sc-qa-native-docker.XXXXXXXX)
# Failure cleanup is the outer harness's strictly test-owned --network none
# Docker container teardown; never blind-delete ambiguous kernel resources.
ip -j -4 route show table all > "$scratch/host-routes4"
ip -j -6 route show table all > "$scratch/host-routes6"
ip -j -4 rule show > "$scratch/host-rules4"
ip -j -6 rule show > "$scratch/host-rules6"
nft -j list ruleset > "$scratch/host-nft"
table=3362254344

ip link add scouter0 type dummy
ip link add docker0 type dummy
ip link set scouter0 up
ip link set docker0 up
nft add table ip filter
nft add chain ip filter DOCKER-USER
nft add rule ip filter DOCKER-USER counter return
# These are pre-existing foreign Docker objects, not Core resources.
ip -j -4 route show table all > "$scratch/docker-routes4"
ip -j -6 route show table all > "$scratch/docker-routes6"
ip -j -4 rule show > "$scratch/docker-rules4"
ip -j -6 rule show > "$scratch/docker-rules6"
nft -j list ruleset > "$scratch/docker-nft"

stage_stopped_core() {
  # The Core is deliberately not started: reproduce its exact residual
  # kernel footprint after loss, with a fixed unique QA-only table.
  ip -4 route add table "$table" local 127.0.0.1 dev scouter0
  # IRA-124 retained two equal-prefix/equal-metric local routes in the same
  # Core table. A second 'add' is rejected as EEXIST; 'append' reconstructs
  # the distinct Docker bridge alias without replacing the underlay route.
  ip -4 route append table "$table" local 127.0.0.1 dev docker0
  ip -6 route add table "$table" local ::1 dev scouter0 metric 1024
  for family in -4 -6; do
    ip "$family" rule add pref 1 table "$table"
    ip "$family" rule add pref 14202 nop
    ip "$family" rule add pref 14201 fwmark 0x2023 table 27432
    ip "$family" rule add pref 14200 fwmark 0x2024 goto 14202
    ip "$family" rule add pref 32768 not fwmark 0x2024 table 27432
  done
  nft add table inet sing-box
  nft add chain inet sing-box prerouting_prematch
  nft add chain inet sing-box output_prematch
  nft add rule inet sing-box prerouting_prematch iifname '"sctun0"' return
  nft add rule ip filter DOCKER-USER iifname '"sctun0"' counter accept comment '"!sing-box: Docker compatibility input from tun"'
  nft add rule ip filter DOCKER-USER oifname '"sctun0"' counter accept comment '"!sing-box: Docker compatibility output to tun"'
  [ "$(ip -4 route show table "$table" | wc -l)" -eq 2 ]
  [ "$(ip -6 route show table "$table" | wc -l)" -eq 1 ]
}
recover() {
  SC_NATIVE_RECOVERY_GUEST=yes /root/qa-native-recovery-test     -test.run '^TestNativeRedirectStoppedCoreGuest$' -test.v -test.timeout 20s
}
assert_docker_survived() {
  ip -j -4 route show table all > "$scratch/observed-routes4"
  ip -j -6 route show table all > "$scratch/observed-routes6"
  ip -j -4 rule show > "$scratch/observed-rules4"
  ip -j -6 rule show > "$scratch/observed-rules6"
  nft -j list ruleset > "$scratch/observed-nft"
  for part in routes4 routes6 rules4 rules6 nft; do
    cmp -s "$scratch/docker-$part" "$scratch/observed-$part" || {
      echo "NATIVE_DOCKER_RECOVERY_DRIFT=$part" >&2
      return 1
    }
  done
  echo 'NATIVE_DOCKER_FOREIGN_DOCKER_OBJECTS_PRESERVED=PASS'
}
stage_stopped_core
recover
assert_docker_survived
echo 'NATIVE_DOCKER_SIGKILL_LAYOUT_RECOVERY=PASS (real kernel/nft, source-built recovery)'

# Negative case: an additional local foreign bridge in the same random
# table must prevent ALL mutations, not just survive a partial cleanup.
stage_stopped_core
ip link add br-foreign type dummy
ip link set br-foreign up
ip -4 route add table "$table" local 127.0.0.1 dev br-foreign
ip -j -4 route show table all > "$scratch/conflict-routes4"
ip -j -6 route show table all > "$scratch/conflict-routes6"
ip -j -4 rule show > "$scratch/conflict-rules4"
ip -j -6 rule show > "$scratch/conflict-rules6"
nft -j list ruleset > "$scratch/conflict-nft"
SC_NATIVE_RECOVERY_GUEST=yes SC_NATIVE_RECOVERY_EXPECT_REFUSAL=yes \
  /root/qa-native-recovery-test -test.run '^TestNativeRedirectStoppedCoreGuest$' -test.v -test.timeout 20s
ip -j -4 route show table all > "$scratch/observed-routes4"
ip -j -6 route show table all > "$scratch/observed-routes6"
ip -j -4 rule show > "$scratch/observed-rules4"
ip -j -6 rule show > "$scratch/observed-rules6"
nft -j list ruleset > "$scratch/observed-nft"
for part in routes4 routes6 rules4 rules6 nft; do
  cmp -s "$scratch/conflict-$part" "$scratch/observed-$part" || {
    echo "NATIVE_DOCKER_FOREIGN_REFUSAL_DRIFT=$part" >&2
    exit 1
  }
done
echo 'NATIVE_DOCKER_FOREIGN_BRIDGE_REFUSAL=PASS (no mutation)'
# Remove only the *QA*-created extra foreign route, then retry normal
# source-built recovery against the same preserved Core identity.
ip -4 route del table "$table" local 127.0.0.1 dev br-foreign
ip link del br-foreign
recover
assert_docker_survived
echo 'NATIVE_DOCKER_FOREIGN_REFUSAL_RETRY=PASS'

# The outer harness owns the disconnected guest, and checks all baseline
# kernel objects again after dropping only this script's dummy Docker setup.
nft delete table ip filter
ip link del docker0
ip link del scouter0
ip -j -4 route show table all > "$scratch/observed-routes4"
ip -j -6 route show table all > "$scratch/observed-routes6"
ip -j -4 rule show > "$scratch/observed-rules4"
ip -j -6 rule show > "$scratch/observed-rules6"
nft -j list ruleset > "$scratch/observed-nft"
for part in routes4 routes6 rules4 rules6 nft; do
  cmp -s "$scratch/host-$part" "$scratch/observed-$part" || {
    echo "NATIVE_DOCKER_GUEST_CLEANUP_DRIFT=$part" >&2
    exit 1
  }
done
rm -rf -- "$scratch"
echo 'NATIVE_DOCKER_GUEST_FULL_BASELINE_RESTORED=PASS'
