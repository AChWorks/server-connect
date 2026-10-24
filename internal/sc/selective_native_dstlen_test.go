package sc

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Native iproute2 policy JSON represents a destination as "dst" plus
// "dstlen". Treating that address alone as a /32 or /128 can hide a
// higher-precedence overlapping prefix and produce a misleading preview.
func TestSelectivePlanNativeRuleDestinationPrefixLength(t *testing.T) {
	tests := []struct {
		name, family, destination, dst, dstlen string
		wantRefused                            bool
	}{
		{"ipv4_partial_overlap", "ipv4", "8.8.8.128/25", "8.8.8.0", "24", true},
		{"ipv4_default", "ipv4", "8.8.8.0/24", "0.0.0.0", "0", true},
		{"ipv6_partial_overlap", "ipv6", "2606:4700:4700::/48", "2606:4700::", "32", true},
		{"ipv4_disjoint", "ipv4", "8.8.8.0/24", "9.9.9.0", "24", false},
		{"ipv4_invalid_length", "ipv4", "8.8.8.0/24", "9.9.9.0", "33", true},
		{"ipv6_invalid_length", "ipv6", "2606:4700:4700::/48", "2607::", "129", true},
		{"ipv4_missing_length", "ipv4", "8.8.8.0/24", "9.9.9.0", "null", true},
		{"ipv4_conflicting_cidr_length", "ipv4", "8.8.8.0/24", "9.9.9.0/24", "25", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			req.Destinations = []string{tt.destination}
			foreignRule := fmt.Sprintf("{\"priority\":100,\"dst\":%q,\"dstlen\":%s,\"table\":100}", tt.dst, tt.dstlen)
			if tt.family == "ipv4" {
				host.IPv4Rules = json.RawMessage("[{\"priority\":0,\"table\":\"local\"}," + foreignRule + ",{\"priority\":32766,\"table\":\"main\"}]")
				host.IPv4Routes = json.RawMessage("[{\"dst\":\"default\",\"dev\":\"eth0\"},{\"dst\":\"default\",\"table\":100,\"dev\":\"eth1\"}]")
			} else {
				host.IPv6Rules = json.RawMessage("[{\"priority\":0,\"table\":\"local\"}," + foreignRule + ",{\"priority\":32766,\"table\":\"main\"}]")
				host.IPv6Routes = json.RawMessage("[{\"dst\":\"default\",\"dev\":\"eth0\"},{\"dst\":\"default\",\"table\":100,\"dev\":\"eth1\"}]")
			}
			plan, err := planFromFixture(t, req, host)
			if tt.wantRefused {
				if ErrorCode(err) != "route_plan_uncertain" || plan.PlanSHA256 != "" || len(plan.Rules) != 0 {
					t.Fatalf("native RPDB destination was not fail-closed: plan=%+v err=%v", plan, err)
				}
			} else if err != nil || !plan.ReadOnly || plan.ActivationReady {
				t.Fatalf("disjoint native RPDB rule should permit advisory-only preview: plan=%+v err=%v", plan, err)
			}
		})
	}
}

// The parser itself must reject null. A planner-only negative case can
// pass accidentally when an invalid 9.9.9.0/0 is rejected as noncanonical.
func TestSelectiveRuleDestinationNullLengthIsInvalid(t *testing.T) {
	cases := []struct {
		name, dst string
		ipv6      bool
	}{
		{"ipv4_native_zero", "0.0.0.0", false},
		{"ipv6_native_zero", "::", true},
		{"ipv4_cidr_zero", "0.0.0.0/0", false},
		{"ipv6_cidr_zero", "::/0", true},
		{"ipv4_all", "all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]json.RawMessage{
				"dst":    json.RawMessage(fmt.Sprintf("%q", tc.dst)),
				"dstlen": json.RawMessage("null"),
			}
			prefix, constrained, err := selectiveRuleDestination(row, tc.ipv6)
			if ErrorCode(err) != "route_plan_uncertain" || prefix.IsValid() || constrained {
				t.Fatalf("null dstlen accepted: prefix=%v constrained=%v err=%v", prefix, constrained, err)
			}
		})
	}
}

func TestSelectiveRuleDestinationNumericZeroIsValid(t *testing.T) {
	for _, tc := range []struct {
		name, dst   string
		ipv6        bool
		constrained bool
	}{
		{"ipv4_native_zero", "0.0.0.0", false, true},
		{"ipv6_native_zero", "::", true, true},
		{"ipv4_cidr_zero", "0.0.0.0/0", false, true},
		{"ipv6_cidr_zero", "::/0", true, true},
		{"ipv4_all", "all", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]json.RawMessage{
				"dst":    json.RawMessage(fmt.Sprintf("%q", tc.dst)),
				"dstlen": json.RawMessage("0"),
			}
			prefix, constrained, err := selectiveRuleDestination(row, tc.ipv6)
			if err != nil || constrained != tc.constrained ||
				(tc.constrained && (!prefix.IsValid() || prefix.Bits() != 0)) ||
				(!tc.constrained && prefix.IsValid()) {
				t.Fatalf("valid numeric /0 was rejected: prefix=%v constrained=%v err=%v", prefix, constrained, err)
			}
		})
	}
}

// A foreign earlier lookup without a default or matching route must not
// mask malformed dstlen. Without explicit rejection the /0 selector can
// silently fall through and produce a successful advisory plan.
func TestSelectivePlanRejectsNullDstlenWithoutForeignDefault(t *testing.T) {
	for _, tc := range []struct {
		name, dst, destination string
		ipv6                   bool
	}{
		{"ipv4_native_zero", "0.0.0.0", "8.8.8.0/24", false},
		{"ipv6_native_zero", "::", "2606:4700:4700::/48", true},
		{"ipv4_cidr_zero", "0.0.0.0/0", "8.8.8.0/24", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			req.Destinations = []string{tc.destination}
			rule := fmt.Sprintf("{\"priority\":100,\"dst\":%q,\"dstlen\":null,\"table\":100}", tc.dst)
			if tc.ipv6 {
				host.IPv6Rules = json.RawMessage("[{\"priority\":0,\"table\":\"local\"}," + rule + ",{\"priority\":32766,\"table\":\"main\"}]")
			} else {
				host.IPv4Rules = json.RawMessage("[{\"priority\":0,\"table\":\"local\"}," + rule + ",{\"priority\":32766,\"table\":\"main\"}]")
			}
			// The foreign table is empty in both families, by design.
			plan, err := planFromFixture(t, req, host)
			if ErrorCode(err) != "route_plan_uncertain" || plan.PlanSHA256 != "" ||
				len(plan.Routes) != 0 || len(plan.Rules) != 0 {
				t.Fatalf("invalid foreign rule produced an advisory plan: plan=%+v err=%v", plan, err)
			}
		})
	}
}

func TestSelectiveIntDoesNotNormalizeNullToZero(t *testing.T) {
	if number, valid := selectiveInt(json.RawMessage("null")); valid {
		t.Fatalf("JSON null was accepted as integer %d", number)
	}
	for _, raw := range []string{"0", "\"0\""} {
		if number, valid := selectiveInt(json.RawMessage(raw)); !valid || number != 0 {
			t.Fatalf("valid numeric zero %s was rejected: %d %v", raw, number, valid)
		}
	}
}

// Reusing the numeric parser must also reject null in existing rule identities,
// rather than inventing priority zero or reserving a fictitious table zero.
func TestSelectivePlanNullRulePriorityOrTableFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, rule string }{
		{"null_priority", "{\"priority\":null,\"table\":100}"},
		{"null_table", "{\"priority\":100,\"table\":null}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			req.Destinations = []string{"8.8.8.0/24"}
			host.IPv4Rules = json.RawMessage("[{\"priority\":0,\"table\":\"local\"}," + tc.rule + ",{\"priority\":32766,\"table\":\"main\"}]")
			plan, err := planFromFixture(t, req, host)
			if ErrorCode(err) != "route_plan_uncertain" || plan.PlanSHA256 != "" ||
				len(plan.Routes) != 0 || len(plan.Rules) != 0 {
				t.Fatalf("null rule identity was trusted: plan=%+v err=%v", plan, err)
			}
		})
	}
}
