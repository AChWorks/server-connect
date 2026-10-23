package sc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func fixtureSelectiveHost() HostPreflight {
	return HostPreflight{
		Mode: "observation_only", ReadOnly: true,
		Links:          json.RawMessage(`[{"ifname":"lo"},{"ifname":"eth0"}]`),
		IPv4Routes:     json.RawMessage(`[{"dst":"default","dev":"eth0"},{"dst":"192.0.2.0/24","dev":"eth0"}]`),
		IPv6Routes:     json.RawMessage(`[{"dst":"fe80::/64","dev":"eth0"},{"dst":"default","dev":"eth0"}]`),
		IPv4Rules:      json.RawMessage(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"},{"priority":32767,"table":"default"}]`),
		IPv6Rules:      json.RawMessage(`[{"priority":0,"table":"local"},{"priority":32766,"table":"main"}]`),
		Endpoint:       &HostRouteLookup{Target: "198.51.100.1", Family: "ipv4", KernelRoute: json.RawMessage(`[{"dst":"198.51.100.1","gateway":"192.0.2.1","dev":"eth0"}]`)},
		ManagementPeer: &HostRouteLookup{Target: "198.51.100.2", Family: "ipv4", KernelRoute: json.RawMessage(`[{"dst":"198.51.100.2","gateway":"192.0.2.1","dev":"eth0"}]`)},
	}
}

func fixtureSelectiveRequest() SelectivePlanRequest {
	return SelectivePlanRequest{
		EndpointIP: "198.51.100.1", ManagementPeerIP: "198.51.100.2",
		TunnelInterface: "scplan0", Destinations: []string{"2606:4700:4700::/48", "8.8.8.0/24"},
	}
}

func planFromFixture(t *testing.T, req SelectivePlanRequest, h HostPreflight) (SelectiveRoutePlan, error) {
	t.Helper()
	intent, err := validateSelectiveRequest(req)
	if err != nil {
		return SelectiveRoutePlan{}, err
	}
	return buildSelectivePlan(intent, h)
}

func TestSelectivePlanDeterminismAndNoApproval(t *testing.T) {
	host := fixtureSelectiveHost()
	req := fixtureSelectiveRequest()
	a, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	if a.Mode != "selective_preview" || !a.ReadOnly || a.ActivationReady ||
		a.GuardArmed || a.OwnershipVerified || a.SnapshotAtomic ||
		a.RouteTable != selectiveFirstTable || len(a.Routes) != 2 || len(a.Rules) != 2 ||
		len(a.PlanSHA256) != 64 || len(a.ObservationSHA256) != 64 {
		t.Fatalf("preview promised unsupported activation or omitted planned resources: %+v", a)
	}
	if a.Routes[0].Destination != "2606:4700:4700::/48" || a.Routes[0].Family != "ipv6" ||
		a.Rules[1].Family != "ipv4" || a.Rules[1].Priority != 30001 {
		t.Fatalf("unexpected deterministic order or family: %+v", a)
	}
	req.Destinations[0], req.Destinations[1] = req.Destinations[1], req.Destinations[0]
	b, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("unordered operator input changed canonical plan: A=%+v B=%+v", a, b)
	}
	// Changes to observed state invalidate the exact plan digest even when
	// the selected route table and candidate operations remain identical.
	host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0","metric":777},{"dst":"192.0.2.0/24","dev":"eth0"}]`)
	c, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	if c.PlanSHA256 == b.PlanSHA256 || c.ObservationSHA256 == b.ObservationSHA256 {
		t.Fatal("observed host drift did not invalidate plan fingerprint")
	}
}

func TestSelectivePlanCollisionAndRefusal(t *testing.T) {
	tests := []struct {
		name string
		edit func(*SelectivePlanRequest, *HostPreflight)
		code string
	}{
		{"existing_device", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.Links = json.RawMessage(`[{"ifname":"lo"},{"ifname":"scplan0"}]`)
		}, "route_plan_uncertain"},
		{"existing_specific_route", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0"},{"dst":"8.8.8.0/24","dev":"eth0"}]`)
		}, "route_plan_uncertain"},
		{"overlap_host_route", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.IPv4Routes = json.RawMessage(`[{"dst":"8.8.0.0/16","dev":"eth0"}]`)
		}, "route_plan_uncertain"},
		{"unknown_table_alias", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.IPv4Rules = json.RawMessage(`[{"priority":100,"table":"client_custom"}]`)
		}, "route_plan_uncertain"},
		{"missing_policy_table", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.IPv4Rules = json.RawMessage(`[{"priority":100,"action":"nop"}]`)
		}, "route_plan_uncertain"},
		{"bad_policy_json", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.IPv4Rules = json.RawMessage(`{"not":"array"}`)
		}, "route_plan_uncertain"},
		{"mismatched_protected_peer", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.ManagementPeer.Target = "1.2.3.4"
		}, "route_plan_uncertain"},
		{"not_explicitly_read_only", func(r *SelectivePlanRequest, h *HostPreflight) {
			h.ReadOnly = false
		}, "route_plan_uncertain"},
		{"endpoint_captured", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"198.51.100.0/24"}
		}, "invalid_arguments"},
		{"management_captured", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"198.51.100.2/32"}
		}, "invalid_arguments"},
		{"destinations_overlap", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"8.8.8.0/24", "8.8.8.8/32"}
		}, "invalid_arguments"},
		{"default_broad", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"0.0.0.0/0"}
		}, "invalid_arguments"},
		{"too_broad", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"8.0.0.0/7"}
		}, "invalid_arguments"},
		{"carrier_grade_nat", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"100.64.0.0/10"}
		}, "invalid_arguments"},
		{"documentation_ipv4", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"203.0.113.0/24"}
		}, "invalid_arguments"},
		{"documentation_ipv6", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"2001:db8::/32"}
		}, "invalid_arguments"},
		{"private_route", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"10.0.0.0/8"}
		}, "invalid_arguments"},
		{"link_local_v6", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"fe80::/32"}
		}, "invalid_arguments"},
		{"noncanonical", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = []string{"8.8.8.7/24"}
		}, "invalid_arguments"},
		{"invalid_interface", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.TunnelInterface = "bad;device"
		}, "invalid_arguments"},
		{"no_peer", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.ManagementPeerIP = ""
		}, "invalid_arguments"},
		{"loopback_endpoint", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.EndpointIP = "127.0.0.1"
		}, "invalid_arguments"},
		{"no_destinations", func(r *SelectivePlanRequest, h *HostPreflight) {
			r.Destinations = nil
		}, "invalid_arguments"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			tt.edit(&req, &host)
			p, err := planFromFixture(t, req, host)
			if err == nil || ErrorCode(err) != tt.code {
				t.Fatalf("expected %s, got plan=%+v err=%v", tt.code, p, err)
			}
			if p.PlanSHA256 != "" || len(p.Rules) > 0 {
				t.Fatalf("unsafe partial plan escaped rejection: %+v", p)
			}
		})
	}
}

func TestSelectivePlanRefusesOccupiedAlternateLinkName(t *testing.T) {
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	host.Links = json.RawMessage(`[{"ifname":"lo"},{"ifname":"eth0","altnames":["scplan0"]}]`)
	plan, err := planFromFixture(t, req, host)
	if ErrorCode(err) != "route_plan_uncertain" || plan.PlanSHA256 != "" {
		t.Fatalf("alternate Linux interface name would be adopted: plan=%+v err=%v", plan, err)
	}
}

func TestSelectivePlanCollisionSkipsOccupiedIdentifiers(t *testing.T) {
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	host.IPv4Rules = json.RawMessage(`[{"priority":0,"table":"local"},{"priority":30000,"table":20000},{"priority":32766,"table":"main"}]`)
	plan, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	if plan.RouteTable != 20001 || plan.Rules[0].Priority != 30001 ||
		plan.Rules[1].Priority != 30002 {
		t.Fatalf("foreign table/rule IDs reused: %+v", plan)
	}
}

func TestSelectivePlanNeverClaimsProtectionByFieldOmission(t *testing.T) {
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	plan, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"read_only":true`, `"activation_ready":false`,
		`"guard_armed":false`, `"ownership_verified":false`,
		`"snapshot_atomic":false`,
	} {
		if !strings.Contains(string(b), field) {
			t.Fatalf("missing explicit negative assertion %s in %s", field, string(b))
		}
	}
}

func TestSelectivePlanRPDBPrecedence(t *testing.T) {
	// A rule with a smaller priority number runs first and may terminate
	// lookup through an existing table default, even without CIDR overlap.
	tests := []struct {
		name  string
		rule  string
		route string
		ok    bool
	}{
		{"unconditional_table_default", `{"priority":100,"src":"all","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, false},
		{"unconditional_numeric_default", `{"priority":100,"table":100}`, `{"dst":"0.0.0.0/0","table":100,"dev":"eth1"}`, false},
		{"early_main_default", `{"priority":100,"table":"main"}`, "", false},
		{"source_specific_default", `{"priority":100,"src":"10.0.0.0/8","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, false},
		{"mark_specific_default", `{"priority":100,"fwmark":"0x1","fwmask":"0xffffffff","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, false},
		{"destination_overlap", `{"priority":100,"dst":"8.8.0.0/16","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, false},
		{"destination_disjoint", `{"priority":100,"dst":"9.9.9.0/24","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, true},
		{"source_rule_no_matching_route", `{"priority":100,"src":"10.0.0.0/8","table":100}`, `{"dst":"9.9.9.0/24","table":100,"dev":"eth1"}`, true},
		{"mark_rule_no_matching_route", `{"priority":100,"fwmark":"0x1","table":100}`, `{"dst":"9.9.9.0/24","table":100,"dev":"eth1"}`, true},
		{"inverted_destination_disjoint", `{"priority":100,"not":true,"dst":"9.9.9.0/24","table":100}`, `{"dst":"default","table":100,"dev":"eth1"}`, false},
		{"unsupported_rule_action", `{"priority":100,"action":"unreachable","table":100}`, "", false},
		{"unsupported_suppressor", `{"priority":100,"table":100,"suppress_prefixlength":0}`, "", false},
		{"unsupported_l3mdev", `{"priority":100,"table":100,"l3mdev":true}`, "", false},
		{"unsupported_unknown_selector", `{"priority":100,"table":100,"opaque_selector":1}`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
			req.Destinations = []string{"8.8.8.0/24"}
			host.IPv4Rules = json.RawMessage(`[{"priority":0,"src":"all","table":"local"},` + tt.rule + `,{"priority":32766,"src":"all","table":"main"}]`)
			if tt.route != "" {
				host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0"},` + tt.route + `]`)
			}
			plan, err := planFromFixture(t, req, host)
			if tt.ok {
				if err != nil || !plan.ReadOnly || plan.ActivationReady {
					t.Fatalf("expected safe advisory-only plan: plan=%+v err=%v", plan, err)
				}
			} else if ErrorCode(err) != "route_plan_uncertain" || len(plan.Rules) != 0 || plan.PlanSHA256 != "" {
				t.Fatalf("expected fail-closed uncertain route plan: plan=%+v err=%v", plan, err)
			}
		})
	}
}

func TestSelectivePlanRejectsInterleavedPolicyAndIPv6Default(t *testing.T) {
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	req.Destinations = []string{"8.8.8.0/24", "9.9.9.0/24"}
	host.IPv4Rules = json.RawMessage(`[{"priority":0,"table":"local"},{"priority":30001,"table":100},{"priority":32766,"table":"main"}]`)
	host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0"},{"dst":"default","table":100,"dev":"eth1"}]`)
	plan, err := planFromFixture(t, req, host)
	if ErrorCode(err) != "route_plan_uncertain" || len(plan.Rules) != 0 {
		t.Fatalf("policy interleaved between planned priorities was missed: plan=%+v err=%v", plan, err)
	}

	req, host = fixtureSelectiveRequest(), fixtureSelectiveHost()
	req.Destinations = []string{"2606:4700:4700::/48"}
	host.IPv6Rules = json.RawMessage(`[{"priority":0,"table":"local"},{"priority":100,"src":"all","table":100},{"priority":32766,"table":"main"}]`)
	host.IPv6Routes = json.RawMessage(`[{"dst":"default","table":100,"dev":"eth1"},{"dst":"fe80::/64","dev":"eth0"}]`)
	plan, err = planFromFixture(t, req, host)
	if ErrorCode(err) != "route_plan_uncertain" || len(plan.Rules) != 0 {
		t.Fatalf("IPv6 earlier table default was ignored: plan=%+v err=%v", plan, err)
	}
}

func TestSelectivePlanFingerprintProtectsRouteLookups(t *testing.T) {
	req, host := fixtureSelectiveRequest(), fixtureSelectiveHost()
	baseline, err := planFromFixture(t, req, host)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name string
		edit func(*HostPreflight)
	}{
		{"endpoint_route_gateway", func(h *HostPreflight) {
			h.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.1","gateway":"192.0.2.99","dev":"eth0"}]`)
		}},
		{"endpoint_route_device", func(h *HostPreflight) {
			h.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.1","gateway":"192.0.2.1","dev":"eth2"}]`)
		}},
		{"management_route_gateway", func(h *HostPreflight) {
			h.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.2","gateway":"192.0.2.99","dev":"eth0"}]`)
		}},
		{"management_route_device", func(h *HostPreflight) {
			h.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"198.51.100.2","gateway":"192.0.2.1","dev":"eth2"}]`)
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			h := fixtureSelectiveHost()
			tt.edit(&h)
			plan, err := planFromFixture(t, req, h)
			if err != nil || plan.PlanSHA256 == baseline.PlanSHA256 ||
				plan.ObservationSHA256 == baseline.ObservationSHA256 {
				t.Fatalf("protected route drift was not fingerprinted: plan=%+v err=%v", plan, err)
			}
		})
	}
	// Different key order and whitespace are the same observation.
	host.Endpoint.KernelRoute = json.RawMessage(`[ { "dev":"eth0", "gateway":"192.0.2.1", "dst":"198.51.100.1" } ]`)
	host.ManagementPeer.KernelRoute = json.RawMessage(`[{"gateway":"192.0.2.1", "dst":"198.51.100.2", "dev":"eth0"}]`)
	host.IPv4Routes = json.RawMessage(`[{"dev":"eth0","dst":"default"},{"dev":"eth0", "dst":"192.0.2.0/24"}]`)
	same, err := planFromFixture(t, req, host)
	if err != nil || same.ObservationSHA256 != baseline.ObservationSHA256 ||
		same.PlanSHA256 != baseline.PlanSHA256 {
		t.Fatalf("equivalent observation JSON changed canonical digest: plan=%+v err=%v", same, err)
	}
}

func TestSelectivePlanRejectsUnsupportedProtectedLookupEvidence(t *testing.T) {
	tests := []struct {
		name string
		edit func(*HostPreflight)
	}{
		{"missing_endpoint_payload", func(h *HostPreflight) { h.Endpoint.KernelRoute = nil }},
		{"empty_management_payload", func(h *HostPreflight) { h.ManagementPeer.KernelRoute = json.RawMessage(`[]`) }},
		{"wrong_endpoint_family", func(h *HostPreflight) { h.Endpoint.Family = "ipv6" }},
		{"wrong_management_destination", func(h *HostPreflight) {
			h.ManagementPeer.KernelRoute = json.RawMessage(`[{"dst":"8.8.8.8","dev":"eth0"}]`)
		}},
		{"missing_endpoint_destination", func(h *HostPreflight) {
			h.Endpoint.KernelRoute = json.RawMessage(`[{"gateway":"192.0.2.1","dev":"eth0"}]`)
		}},
		{"missing_management_reference", func(h *HostPreflight) { h.ManagementPeer = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, h := fixtureSelectiveRequest(), fixtureSelectiveHost()
			tt.edit(&h)
			p, err := planFromFixture(t, req, h)
			if ErrorCode(err) != "route_plan_uncertain" || p.PlanSHA256 != "" || len(p.Routes) != 0 {
				t.Fatalf("invalid protected lookup evidence escaped fail-closed planner: plan=%+v err=%v", p, err)
			}
		})
	}
}
