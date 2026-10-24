package sc

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This exercises real Linux RPDB/route lookup semantics on disposable devices,
// without a VPN, packet transmission, a production applier, or a recovery guard.
// All network mutations are fixed shell arguments of unshare -Urn: the shell
// cannot start on the host if creation of the private namespaces fails.
func TestSelectivePolicyKernelRoutingInPrivateNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux network namespaces required")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("trusted native iproute2 unavailable")
	}
	requireDisposableUserNetNamespace(t)

	const script = `set -eu
ip=/usr/bin/ip
"$ip" link add scdirect0 type dummy
"$ip" link add scplan0 type dummy
"$ip" link set scdirect0 up
"$ip" link set scplan0 up
"$ip" -4 addr add 192.0.2.2/24 dev scdirect0
"$ip" -6 addr add 2001:db8:ffff::2/64 dev scdirect0
"$ip" -4 addr add 10.200.0.2/24 dev scplan0
"$ip" -6 addr add fd00:200::2/64 dev scplan0
"$ip" -4 route add default via 192.0.2.1 dev scdirect0
"$ip" -6 route add default via 2001:db8:ffff::1 dev scdirect0

check() {
	printf '%s\t' "$1"
	shift
	"$ip" -j "$@"
}
check before_ipv4_selected -4 route get 8.8.8.8
check before_ipv6_selected -6 route get 2606:4700:4700::1111

# Candidate policy from the read-only planner: two separate exact routes,
# in one previously empty table, at two unused distinct rule priorities.
"$ip" -4 route add 8.8.8.0/24 dev scplan0 table 20000
"$ip" -6 route add 2606:4700:4700::/48 dev scplan0 table 20000
"$ip" -4 rule add pref 30001 to 8.8.8.0/24 table 20000
"$ip" -6 rule add pref 30000 to 2606:4700:4700::/48 table 20000
check selected_ipv4 -4 route get 8.8.8.8
check selected_ipv6 -6 route get 2606:4700:4700::1111
check protected_endpoint -4 route get 198.51.100.1
check protected_management -4 route get 198.51.100.2
check unrelated_ipv4 -4 route get 1.1.1.1
check unrelated_ipv6 -6 route get 2001:4860:4860::8888

# A third party adds a DIFFERENT route/rule to the same table during the
# trial. Exact-key rollback of ours must leave those objects alone.
"$ip" -4 route add 9.9.9.0/24 dev scdirect0 table 20000
"$ip" -4 rule add pref 30010 to 9.9.9.0/24 table 20000
check foreign_before_rollback -4 route get 9.9.9.9

# A higher-precedence foreign rule with a matching specific route overrides
# a lower-precedence selected rule even if the selected policy still exists.
# This validates the reason the planner refuses overlapping host routes.
"$ip" -4 route add 8.8.8.0/24 dev scdirect0 table 20100
"$ip" -4 rule add pref 100 to 8.8.8.0/24 table 20100
check native_foreign_rule -4 rule show
check intercepted_ipv4 -4 route get 8.8.8.8
"$ip" -4 rule del pref 100 to 8.8.8.0/24 table 20100
"$ip" -4 route del 8.8.8.0/24 dev scdirect0 table 20100
check resumed_ipv4 -4 route get 8.8.8.8

# This is ONLY a private-namespace kernel semantics fixture, not product
# rollback code. Never flush either table or the host's unrelated rules.
"$ip" -4 rule del pref 30001 to 8.8.8.0/24 table 20000
"$ip" -6 rule del pref 30000 to 2606:4700:4700::/48 table 20000
"$ip" -4 route del 8.8.8.0/24 dev scplan0 table 20000
"$ip" -6 route del 2606:4700:4700::/48 dev scplan0 table 20000
check restored_ipv4_selected -4 route get 8.8.8.8
check restored_ipv6_selected -6 route get 2606:4700:4700::1111
check foreign_after_rollback -4 route get 9.9.9.9
check foreign_route_persisted -4 route show table 20000
printf 'ipv6_table_after_rollback\t'
"$ip" -j -6 route show table 20000
printf 'ipv4_rules_after_rollback\t'
"$ip" -j -4 rule show
printf 'ipv6_rules_after_rollback\t'
"$ip" -j -6 rule show
check restored_endpoint -4 route get 198.51.100.1
check restored_management -4 route get 198.51.100.2
check restored_unrelated_ipv4 -4 route get 1.1.1.1
check restored_unrelated_ipv6 -6 route get 2001:4860:4860::8888`

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stdout, stderr, err := runBoundedTestProcess(ctx,
		"/usr/bin/unshare", "-Urn", "/usr/bin/sh", "-c", script)
	if err != nil || ctx.Err() != nil {
		t.Fatalf("isolated route policy fixture failed: err=%v ctx=%v stderr=%s stdout=%s",
			err, ctx.Err(), stderr, stdout)
	}

	// Read-only parsing of the kernel's JSON reports in the parent test
	// process; no subprocess selector or environment marker can mutate a host.
	devices := map[string]string{
		"before_ipv4_selected":    "scdirect0",
		"before_ipv6_selected":    "scdirect0",
		"selected_ipv4":           "scplan0",
		"selected_ipv6":           "scplan0",
		"protected_endpoint":      "scdirect0",
		"protected_management":    "scdirect0",
		"unrelated_ipv4":          "scdirect0",
		"unrelated_ipv6":          "scdirect0",
		"foreign_before_rollback": "scdirect0",
		"intercepted_ipv4":        "scdirect0",
		"resumed_ipv4":            "scplan0",
		"restored_ipv4_selected":  "scdirect0",
		"restored_ipv6_selected":  "scdirect0",
		"foreign_after_rollback":  "scdirect0",
		"foreign_route_persisted": "scdirect0",
		"restored_endpoint":       "scdirect0",
		"restored_management":     "scdirect0",
		"restored_unrelated_ipv4": "scdirect0",
		"restored_unrelated_ipv6": "scdirect0",
	}
	seen := make(map[string]bool, len(devices))
	foreignPolicyFound := false
	ruleReportsSeen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(stdout)), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("invalid isolated route-get record %q", line)
		}
		name, raw := parts[0], parts[1]
		if name == "native_foreign_rule" {
			if seen[name] {
				t.Fatal("duplicate native foreign rule capture")
			}
			seen[name] = true
			var rules []map[string]json.RawMessage
			if err := json.Unmarshal([]byte(raw), &rules); err != nil || len(rules) == 0 {
				t.Fatalf("invalid native RPDB rule report: %v (%q)", err, raw)
			}
			found := false
			for _, rule := range rules {
				if priority, ok := selectiveInt(rule["priority"]); ok && priority == 100 {
					bits, ok := selectiveInt(rule["dstlen"])
					found = ok && bits == 24 && selectiveText(rule["dst"]) == "8.8.8.0"
				}
			}
			if !found {
				t.Fatalf("native iproute2 did not expose the expected separate dst/dstlen: %s", raw)
			}
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			req.Destinations = []string{"8.8.8.128/25"}
			host.IPv4Rules = json.RawMessage(raw)
			host.IPv4Routes = json.RawMessage("[{\"dst\":\"default\",\"dev\":\"eth0\"},{\"dst\":\"default\",\"table\":20100,\"dev\":\"eth1\"}]")
			plan, err := planFromFixture(t, req, host)
			if ErrorCode(err) != "route_plan_uncertain" || plan.PlanSHA256 != "" || len(plan.Rules) != 0 {
				t.Fatalf("captured native higher-priority rule was ignored: plan=%+v err=%v", plan, err)
			}
			continue
		}
		if name == "ipv6_table_after_rollback" {
			if seen[name] {
				t.Fatal("duplicate IPv6 owned-table evidence")
			}
			seen[name] = true
			var routes []json.RawMessage
			if err := json.Unmarshal([]byte(raw), &routes); err != nil || routes == nil || len(routes) != 0 {
				t.Fatalf("owned IPv6 table retained orphaned route after exact fixture cleanup: %s (%v)", raw, err)
			}
			continue
		}
		if name == "ipv4_rules_after_rollback" || name == "ipv6_rules_after_rollback" {
			if ruleReportsSeen[name] {
				t.Fatalf("duplicate native policy evidence: %s", name)
			}
			ruleReportsSeen[name] = true
			var rules []map[string]json.RawMessage
			if err := json.Unmarshal([]byte(raw), &rules); err != nil || rules == nil {
				t.Fatalf("invalid native rule evidence for %s: %v (%q)", name, err, raw)
			}
			for _, rule := range rules {
				priority, ok := selectiveInt(rule["priority"])
				if !ok {
					t.Fatalf("invalid native rule priority in %s: %s", name, raw)
				}
				if priority == 30000 || priority == 30001 {
					t.Errorf("selected policy rule survived exact fixture cleanup in %s: %s", name, raw)
				}
				if name == "ipv4_rules_after_rollback" && priority == 30010 {
					table, err := selectiveTable(rule["table"], false)
					var prefixBits int
					prefixErr := json.Unmarshal(rule["dstlen"], &prefixBits)
					// Debian 13 iproute2 emits dst + dstlen separately for
					// native policy rules (unlike route prefix JSON).
					foreignPolicyFound = err == nil && prefixErr == nil && table == 20000 &&
						selectiveText(rule["dst"]) == "9.9.9.0" && prefixBits == 24
				}
			}
			continue
		}
		wantDev, ok := devices[name]
		if !ok || seen[name] {
			t.Fatalf("unknown or duplicate isolated route-get stage %q", name)
		}
		seen[name] = true
		var routes []struct {
			Device      string `json:"dev"`
			Destination string `json:"dst"`
		}
		if err := json.Unmarshal([]byte(raw), &routes); err != nil || len(routes) != 1 {
			t.Fatalf("invalid native kernel route-get for %s: %v (%q)", name, err, raw)
		}
		if name == "foreign_route_persisted" && routes[0].Destination != "9.9.9.0/24" {
			t.Errorf("foreign route was lost or replaced: %s", raw)
		}
		if routes[0].Device != wantDev {
			t.Errorf("kernel selected %s at %s, expected %s", routes[0].Device, name, wantDev)
		}
	}
	for name := range devices {
		if !seen[name] {
			t.Errorf("missing native kernel route-get evidence for %s", name)
		}
	}
	if !ruleReportsSeen["ipv4_rules_after_rollback"] ||
		!ruleReportsSeen["ipv6_rules_after_rollback"] ||
		!seen["ipv6_table_after_rollback"] || !seen["native_foreign_rule"] || !foreignPolicyFound {
		t.Errorf("owned cleanup evidence incomplete or foreign policy lost: rules=%v v6_table=%v foreign=%v",
			ruleReportsSeen, seen["ipv6_table_after_rollback"], foreignPolicyFound)
	}
	if t.Failed() {
		t.Logf("native iproute2 stdout: %s\nnative stderr: %s", stdout, stderr)
	}
}

func TestSelectiveKernelPolicyFixtureScope(t *testing.T) {
	// Independently exercise the public planner's safety claims using the
	// matching fixture destinations, without executing any namespace script.
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	plan, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Rules) != 2 || len(plan.Routes) != 2 ||
		plan.Rules[0].Priority != 30000 || plan.Rules[1].Priority != 30001 ||
		plan.Routes[0].Table != 20000 || plan.Routes[1].Table != 20000 ||
		plan.Routes[0].Device != "scplan0" || plan.Routes[1].Device != "scplan0" {
		t.Fatalf("kernel fixture no longer corresponds to planned route/rule identity: %+v", plan)
	}
	if plan.ActivationReady || plan.GuardArmed || plan.OwnershipVerified || !plan.ReadOnly {
		t.Fatalf("routing fixture promoted advisory preview to activation: %+v", plan)
	}
	for _, tc := range []struct {
		family, destination string
		priority            int
	}{
		{"ipv6", "2606:4700:4700::/48", 30000},
		{"ipv4", "8.8.8.0/24", 30001},
	} {
		found := false
		for _, rule := range plan.Rules {
			if rule.Family == tc.family && rule.Destination == tc.destination {
				if rule.Priority != tc.priority {
					t.Fatalf("unexpected planner priority for %s: %d", tc.destination, rule.Priority)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("missing planned route for %s", tc.destination)
		}
	}
}
