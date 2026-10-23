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
