package sc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testSelectedHostReadinessManager(t *testing.T, server string) *Manager {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	state := State{Version: 1, Desired: "direct", Selected: "0123456789abcdef", Port: DefaultPort}
	b, _ := json.Marshal(state)
	if err := os.WriteFile(filepath.Join(root, "state.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	profile := Profile{
		ID: state.Selected, Kind: "vless-link",
		Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"` + server + `","server_port":443,"uuid":"SECRET_UUID_12345"}`),
	}
	b, _ = json.Marshal(profile)
	if err := os.WriteFile(filepath.Join(root, "profiles", profile.ID+".json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	return New(root, DefaultCore, DefaultPort)
}

func testSelectedHostReadinessProbes() (smartTUNHostReadinessProbes, *map[string]int) {
	calls := map[string]int{}
	probes := smartTUNHostReadinessProbes{
		dns: func(host, endpoint, resolver string, port int, expectedDevice string) (UnderlayDNSReport, error) {
			calls["dns"]++
			if host != "private.example.com" || endpoint != "8.8.8.8" || resolver != "1.1.1.1" || port != 53 || expectedDevice != "ens3" {
				return UnderlayDNSReport{}, errors.New("unexpected probe target")
			}
			return UnderlayDNSReport{
				NameResolved: true, NameMatched: true, InterfaceBound: true, RouteStable: true,
				ResolverRouteDevice: "ens3",
			}, nil
		},
		tcp: func(endpoint string, port int, expectedDevice string) (UnderlayTCPReport, error) {
			calls["tcp"]++
			if endpoint != "8.8.8.8" || port != 443 || expectedDevice != "ens3" {
				return UnderlayTCPReport{}, errors.New("unexpected TCP target")
			}
			return UnderlayTCPReport{SocketConnected: true, InterfaceBound: true, RouteStable: true, RouteDevice: "ens3"}, nil
		},
		routes: func(endpoint, peer string) (HostPreflight, error) {
			calls["routes"]++
			if endpoint != "8.8.8.8" || peer != "198.51.100.7" {
				return HostPreflight{}, errors.New("unexpected route target")
			}
			return HostPreflight{Mode: "observation", ReadOnly: true,
				Endpoint: &HostRouteLookup{Target: endpoint, Family: "ipv4",
					KernelRoute: json.RawMessage(`[{"dst":"8.8.8.8","dev":"ens3"}]`)},
				ManagementPeer: &HostRouteLookup{Target: peer, Family: "ipv4",
					KernelRoute: json.RawMessage(`[{"dst":"198.51.100.7","dev":"ens3"}]`)}}, nil
		},
		nft: func() (HostFirewallObservation, error) {
			calls["nft"]++
			return HostFirewallObservation{Observed: true}, nil
		},
		proxy: func(*Manager) (string, error) {
			calls["proxy"]++
			return "inactive", nil
		},
	}
	return probes, &calls
}

func hasReadinessReason(r SmartTUNHostReadiness, code string) bool {
	for _, x := range r.Reasons {
		if x == code {
			return true
		}
	}
	return false
}

func testSelectedHostOutbound(t *testing.T, m *Manager, outbound string) {
	t.Helper()
	path := filepath.Join(m.Dir, "profiles", "0123456789abcdef.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile Profile
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	profile.Outbound = json.RawMessage(outbound)
	b, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedHostCheckTransportAndDialPathClassification(t *testing.T) {
	for _, tc := range []struct {
		name, extra, wantTransport string
		blocked                    bool
	}{
		{"default TCP", "", "tcp", false},
		{"explicit TCP network", `"network":"tcp"`, "tcp", false},
		{"WebSocket TCP", `"transport":{"type":"ws","path":"/private"}`, "ws", false},
		{"HTTPUpgrade TCP", `"transport":{"type":"httpupgrade"}`, "httpupgrade", false},
		{"HTTP transport TCP", `"transport":{"type":"http"}`, "http", false},
		{"HTTP supported host/list headers", `"transport":{"type":"http","host":["example.net"],"headers":{"Accept":["application/json"]}}`, "http", false},
		{"WebSocket supported Host header", `"transport":{"type":"ws","headers":{"Host":"example.net"}}`, "ws", false},
		{"malformed WebSocket path", `"transport":{"type":"ws","path":4}`, "", true},
		{"malformed WebSocket early data", `"transport":{"type":"ws","max_early_data":-1}`, "", true},
		{"malformed HTTP host", `"transport":{"type":"http","host":false}`, "", true},
		{"malformed transport headers", `"transport":{"type":"ws","headers":{"Host":42}}`, "", true},
		{"unsupported transport option", `"transport":{"type":"ws","wrong_field":"value"}`, "", true},
		{"QUIC UDP", `"transport":{"type":"quic"}`, "", true},
		{"unavailable grpc", `"transport":{"type":"grpc"}`, "", true},
		{"unknown transport", `"transport":{"type":"other"}`, "", true},
		{"missing transport type", `"transport":{}`, "", true},
		{"nonobject transport", `"transport":"ws"`, "", true},
		{"null transport", `"transport":null`, "", true},
		{"UDP only network", `"network":"udp"`, "", true},
		{"detour", `"detour":"different-outbound"`, "", true},
		{"custom interface", `"bind_interface":"tun0"`, "", true},
		{"routing mark", `"routing_mark":112`, "", true},
		{"alternate source", `"inet4_bind_address":"192.0.2.4"`, "", true},
		{"alternate network namespace", `"netns":"foreign"`, "", true},
		{"alternate resolver", `"domain_resolver":"elsewhere"`, "", true},
		{"network strategy", `"network_strategy":"fallback"`, "", true},
		{"unknown selector value type", `"routing_mark":{}`, "", true},
		{"explicit default selectors", `"bind_interface":"","routing_mark":0,"network_type":[]`, "tcp", false},
		{"duplicate selected endpoint", `"server":"8.8.8.8"`, "", true},
		{"case-ambiguous selected endpoint", `"SERVER":"8.8.8.8"`, "", true},
		{"duplicate transport header", `"transport":{"type":"ws","headers":{"Host":"a.example","Host":"b.example"}}`, "", true},
		{"case-aliased dial selector", `"bind_interface":"","Bind_Interface":"tun0"`, "", true},
		{"Unicode simple-fold server collision", `"\u017ferver":"8.8.8.8"`, "", true},
		{"Unicode simple-fold nested header collision", `"transport":{"type":"ws","headers":{"Host":"a","Ho\u017ft":"b"}}`, "", true},
		{"Unicode simple-fold nested TLS collision", `"tls":{"server_name":"a","\u017ferver_name":"b"}`, "", true},
		{"duplicate TLS flag", `"tls":{"enabled":false,"enabled":true}`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, "8.8.8.8")
			outbound := `{"type":"vless","server":"8.8.8.8","server_port":443,"uuid":"SECRET_UUID_12345"`
			if tc.extra != "" {
				outbound += "," + tc.extra
			}
			outbound += "}"
			testSelectedHostOutbound(t, m, outbound)
			p, calls := testSelectedHostReadinessProbes()
			r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
			if err != nil || r.ActivationReady || r.GeneralHostAdmitted {
				t.Fatalf("unsafe transport response: %+v err=%v", r, err)
			}
			if tc.blocked {
				if !hasReadinessReason(r, "selected_transport_unsupported") ||
					r.TCP != "not_checked" || r.SelectedTransport != "" ||
					len(*calls) != 0 {
					t.Fatalf("unsupported transport reached probes: %+v calls=%v", r, *calls)
				}
			} else if r.SelectedTransport != tc.wantTransport || r.TCP != "bound_tcp_connected" ||
				(*calls)["tcp"] != 1 {
				t.Fatalf("supported TCP transport not inspected: %+v calls=%v", r, *calls)
			}
			serialized, e := json.Marshal(r)
			if e != nil || strings.Contains(string(serialized), "SECRET_UUID_12345") ||
				strings.Contains(string(serialized), "8.8.8.8") {
				t.Fatal("transport diagnostic leaked selected endpoint or credentials")
			}
		})
	}
}

func TestSelectedHostCheckHostnamePinAndNonAdmittedReport(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, calls := testSelectedHostReadinessProbes()
	report, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || report.ActivationReady || report.GeneralHostAdmitted ||
		report.Mode != "selected_host_readiness" || report.EndpointKind != "hostname" ||
		report.SelectedTransport != "tcp" ||
		report.DNS != "pinned_resolver_observed" || report.TCP != "bound_tcp_connected" ||
		report.HostRoutes != "endpoint_and_management_on_expected_underlay" || report.NativeNFT != "ruleset_observed" ||
		!hasReadinessReason(report, "general_host_admission_not_implemented") {
		t.Fatalf("unsafe or missing readiness result: %+v", report)
	}
	for _, name := range []string{"dns", "tcp", "routes", "nft", "proxy"} {
		want := 1
		if name == "proxy" {
			want = 2
		}
		if (*calls)[name] != want {
			t.Fatalf("%s called %d times, want %d", name, (*calls)[name], want)
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"SECRET_UUID_12345", "private.example.com", "198.51.100.7", "8.8.8.8"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("readiness report leaked selected connection metadata (%q)", secret)
		}
	}
}

func TestSelectedHostCheckDNSFailureCannotReachPinnedTCP(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, calls := testSelectedHostReadinessProbes()
	probes.dns = func(string, string, string, int, string) (UnderlayDNSReport, error) {
		(*calls)["dns"]++
		return UnderlayDNSReport{Outcome: "hostname_mismatch"}, errors.New("mismatch")
	}
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil || r.ActivationReady || r.GeneralHostAdmitted || !hasReadinessReason(r, "endpoint_dns_unverified") ||
		r.TCP != "not_checked" || (*calls)["tcp"] != 0 {
		t.Fatalf("failed DNS unexpectedly authorized or dialed selected endpoint: %+v, %v, calls=%v", r, err, *calls)
	}
}

func TestSelectedHostCheckContradictoryDNSCannotAuthorizeTCP(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, calls := testSelectedHostReadinessProbes()
	probes.dns = func(string, string, string, int, string) (UnderlayDNSReport, error) {
		(*calls)["dns"]++
		// A pin cannot match a name that has not actually resolved.
		return UnderlayDNSReport{
			NameMatched: true, InterfaceBound: true, RouteStable: true,
			ResolverRouteDevice: "ens3",
		}, nil
	}
	report, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil || report.DNS != "unavailable_or_wrong_underlay" || report.TCP != "not_checked" ||
		!hasReadinessReason(report, "endpoint_dns_unverified") || (*calls)["tcp"] != 0 {
		t.Fatalf("contradictory DNS evidence admitted TCP: %+v error=%v calls=%v", report, err, *calls)
	}
}

func TestSelectedHostCheckWrongInterfaceAndNativeNFTMissing(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, _ := testSelectedHostReadinessProbes()
	probes.dns = func(string, string, string, int, string) (UnderlayDNSReport, error) {
		return UnderlayDNSReport{NameMatched: true, InterfaceBound: true, RouteStable: true, ResolverRouteDevice: "docker0"}, nil
	}
	probes.nft = func() (HostFirewallObservation, error) {
		return HostFirewallObservation{}, errors.New("nft binary missing")
	}
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil || r.DNS != "unavailable_or_wrong_underlay" || r.TCP != "not_checked" ||
		r.NativeNFT != "unavailable" || !hasReadinessReason(r, "native_nft_unavailable") || r.ActivationReady {
		t.Fatalf("wrong DNS path or missing nft was accepted: %+v %v", r, err)
	}
}

func TestSelectedHostCheckRefusesForeignOrUnpinnedProfileBeforeProbes(t *testing.T) {
	for _, tc := range []struct {
		server, pinned, resolver string
	}{
		{"private.example.com", "8.8.8.8", ""},
		{"private.example.com", "8.8.8.8", "bad resolver"},
		{"1.1.1.1", "8.8.8.8", ""},
		{"not_a_valid_hostname", "8.8.8.8", "1.1.1.1"},
		{"8.8.8.8", "8.8.8.8", "1.1.1.1"},
	} {
		t.Run(tc.server+"-"+tc.resolver, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, tc.server)
			p, calls := testSelectedHostReadinessProbes()
			r, err := m.inspectSelectedSmartTUNHostWith(tc.pinned, "198.51.100.7", "ens3", tc.resolver, 53, p)
			if (err == nil && !hasReadinessReason(r, "selected_endpoint_not_pinned")) || r.ActivationReady {
				t.Fatal("unsafe activation-ready report")
			}
			for name, count := range *calls {
				if count != 0 {
					t.Fatalf("unsafe probe %s called %d times", name, count)
				}
			}
		})
	}
}

func TestSelectedHostCheckUnselectedNeverCreatesOrProbes(t *testing.T) {
	root := t.TempDir()
	m := New(root, "", DefaultPort)
	p, calls := testSelectedHostReadinessProbes()
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
	if err != nil || r.ActivationReady || !hasReadinessReason(r, "selected_profile_unavailable") {
		t.Fatalf("unselected state not blocked: %+v, %v", r, err)
	}
	for name, count := range *calls {
		if count != 0 {
			t.Fatalf("unexpected probe %s=%d", name, count)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "state.json")); !os.IsNotExist(err) {
		t.Fatal("read-only readiness created state")
	}
}

func TestSelectedHostCheckInvalidArgumentsBeforeStateOrNetwork(t *testing.T) {
	m := New(t.TempDir(), "", DefaultPort)
	p, calls := testSelectedHostReadinessProbes()
	for _, args := range [][5]string{
		{"hostname.test", "198.51.100.7", "ens3", "", "53"},
		{"127.0.0.1", "198.51.100.7", "ens3", "", "53"},
		{"198.51.100.9", "198.51.100.7", "ens3", "", "53"},
		{"8.8.8.8", "", "ens3", "", "53"},
		{"8.8.8.8", "198.51.100.7", "lo/bad", "", "53"},
	} {
		r, err := m.inspectSelectedSmartTUNHostWith(args[0], args[1], args[2], args[3], 53, p)
		if ErrorCode(err) != "invalid_arguments" || r.Mode != "" {
			t.Fatalf("invalid input accepted: %+v %+v %v", args, r, err)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("invalid inputs ran probes: %v", *calls)
	}
}

func TestSelectedHostCheckLiteralEndpointSkipsDNS(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "8.8.8.8")
	p, calls := testSelectedHostReadinessProbes()
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
	if err != nil || r.DNS != "literal_endpoint" || r.TCP != "bound_tcp_connected" ||
		r.EndpointKind != "ipv4" || r.GeneralHostAdmitted || r.ActivationReady ||
		(*calls)["dns"] != 0 || (*calls)["tcp"] != 1 {
		t.Fatalf("literal selected endpoint did not remain pinned: %+v err=%v calls=%v", r, err, *calls)
	}
}

func TestSelectedHostCheckProxyActivityRemainsBlocker(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "8.8.8.8")
	p, _ := testSelectedHostReadinessProbes()
	p.proxy = func(*Manager) (string, error) { return "active", nil }
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
	if err != nil || !hasReadinessReason(r, "proxy_not_inactive") ||
		r.ProxyOnly != "unavailable_or_active" || r.GeneralHostAdmitted || r.ActivationReady {
		t.Fatalf("active Proxy Only received false readiness: %+v %v", r, err)
	}
}

// A simple inactive-to-active service race is a stale snapshot, never a
// current proof that Proxy Only remains inactive.
func TestSelectedHostCheckProxyChangesDuringDiagnostic(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "8.8.8.8")
	p, calls := testSelectedHostReadinessProbes()
	p.proxy = func(*Manager) (string, error) {
		(*calls)["proxy"]++
		if (*calls)["proxy"] == 1 {
			return "inactive", nil
		}
		return "active", nil
	}
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
	if err != nil || r.ProxyOnly != "changed_or_unavailable" ||
		!hasReadinessReason(r, "proxy_state_changed_during_diagnostic") ||
		r.ActivationReady || r.GeneralHostAdmitted || (*calls)["proxy"] != 2 {
		t.Fatalf("stale Proxy Only observation: %+v err=%v calls=%v", r, err, *calls)
	}
}

func TestSelectedHostCheckRefusesWrongOrAmbiguousKernelRoutes(t *testing.T) {
	cases := []struct {
		name, endpointRoute, managementRoute string
	}{
		{"endpoint wrong interface", `[{"dst":"8.8.8.8","dev":"docker0"}]`, `[{"dst":"198.51.100.7","dev":"ens3"}]`},
		{"management wrong interface", `[{"dst":"8.8.8.8","dev":"ens3"}]`, `[{"dst":"198.51.100.7","dev":"docker0"}]`},
		{"endpoint wrong target", `[{"dst":"1.1.1.1","dev":"ens3"}]`, `[{"dst":"198.51.100.7","dev":"ens3"}]`},
		{"multiple ambiguous routes", `[{"dst":"8.8.8.8","dev":"ens3"},{"dst":"8.8.8.8","dev":"ens3"}]`, `[{"dst":"198.51.100.7","dev":"ens3"}]`},
		{"endpoint special route kind", `[{"dst":"8.8.8.8","dev":"ens3","type":"local"}]`, `[{"dst":"198.51.100.7","dev":"ens3"}]`},
		{"malformed route", `[{"dst":"8.8.8.8","dev":0}]`, `[{"dst":"198.51.100.7","dev":"ens3"}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, "8.8.8.8")
			p, _ := testSelectedHostReadinessProbes()
			p.routes = func(endpoint, peer string) (HostPreflight, error) {
				return HostPreflight{Mode: "observation_only", ReadOnly: true,
					Endpoint:       &HostRouteLookup{Target: endpoint, Family: "ipv4", KernelRoute: json.RawMessage(tc.endpointRoute)},
					ManagementPeer: &HostRouteLookup{Target: peer, Family: "ipv4", KernelRoute: json.RawMessage(tc.managementRoute)}}, nil
			}
			r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
			if err != nil || r.HostRoutes != "unavailable_or_wrong_underlay" ||
				!hasReadinessReason(r, "host_routes_unverified") || r.ActivationReady || r.GeneralHostAdmitted {
				t.Fatalf("untrusted route accepted: %+v err=%v", r, err)
			}
		})
	}
}

func TestSelectedHostCheckProfileChangedDuringObservations(t *testing.T) {
	for _, kind := range []string{
		"selection", "state_desired", "state_port", "state_missing",
		"outbound", "profile_kind", "profile_name", "profile_created",
		"profile_missing", "profile_corrupt",
	} {
		t.Run(kind, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, "8.8.8.8")
			p, _ := testSelectedHostReadinessProbes()
			p.nft = func() (HostFirewallObservation, error) {
				switch kind {
				case "selection", "state_desired", "state_port":
					state, err := m.load()
					if err != nil {
						t.Fatal(err)
					}
					switch kind {
					case "selection":
						state.Selected = "fedcba9876543210"
					case "state_desired":
						state.Desired = "proxy"
					case "state_port":
						state.Port++
					}
					if err := m.save(state); err != nil {
						t.Fatal(err)
					}
				case "state_missing":
					if err := os.Remove(filepath.Join(m.Dir, "state.json")); err != nil {
						t.Fatal(err)
					}
				default:
					profilePath := filepath.Join(m.Dir, "profiles", "0123456789abcdef.json")
					data, err := os.ReadFile(profilePath)
					if err != nil {
						t.Fatal(err)
					}
					if kind == "profile_missing" {
						if err := os.Remove(profilePath); err != nil {
							t.Fatal(err)
						}
					} else if kind == "profile_corrupt" {
						if err := os.WriteFile(profilePath, []byte("{invalid"), 0600); err != nil {
							t.Fatal(err)
						}
					} else {
						var profile Profile
						if err := json.Unmarshal(data, &profile); err != nil {
							t.Fatal(err)
						}
						switch kind {
						case "outbound":
							profile.Outbound = json.RawMessage(strings.Replace(string(profile.Outbound), `"server_port":443`, `"server_port":8443`, 1))
						case "profile_kind":
							profile.Kind = "config"
						case "profile_name":
							profile.Name = "another-label"
						case "profile_created":
							profile.Created = "changed"
						}
						changed, err := json.Marshal(profile)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(profilePath, changed, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				return HostFirewallObservation{Observed: true}, nil
			}
			r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, p)
			if err != nil || !hasReadinessReason(r, "selected_profile_changed_during_diagnostic") ||
				r.ActivationReady || r.GeneralHostAdmitted ||
				r.SelectedTransport != "" || r.EndpointKind != "" ||
				r.DNS != "stale_selected_profile" ||
				r.TCP != "stale_selected_profile" ||
				r.HostRoutes != "stale_selected_profile" {
				t.Fatalf("selection drift presented as current evidence: %+v, %v", r, err)
			}
			serialized, err := json.Marshal(r)
			if err != nil || strings.Contains(string(serialized), "SECRET_UUID_12345") ||
				strings.Contains(string(serialized), "8.8.8.8") ||
				strings.Contains(string(serialized), "198.51.100.7") {
				t.Fatal("stale selected-profile diagnostic leaked sensitive connection metadata")
			}
		})
	}
}

// A single noncanonical spelling does not collide with a canonical member,
// so duplicate detection alone cannot protect the struct/map comparison.
func TestSelectedHostCheckStandaloneNoncanonicalPathKeysRefusedBeforeProbes(t *testing.T) {
	const prefix = `{"type":"vless","server":"8.8.8.8","server_port":443,"uuid":"SECRET_UUID_12345"`
	for _, tc := range []struct{ name, outbound string }{
		{"standalone dial interface", prefix + `,"Bind_Interface":"tun0"}`},
		{"standalone alternate detour", prefix + `,"Detour":"other"}`},
		{"standalone network option", prefix + `,"Network":"tcp"}`},
		{"noncanonical endpoint", `{"type":"vless","\u017ferver":"8.8.8.8","server_port":443,"uuid":"SECRET_UUID_12345"}`},
		{"noncanonical endpoint port", `{"type":"vless","server":"8.8.8.8","Server_Port":443,"uuid":"SECRET_UUID_12345"}`},
		{"noncanonical outbound type", `{"Type":"vless","server":"8.8.8.8","server_port":443,"uuid":"SECRET_UUID_12345"}`},
		{"noncanonical transport", prefix + `,"Transport":{"type":"ws"}}`},
		{"noncanonical transport type", prefix + `,"transport":{"Type":"ws"}}`},
		{"noncanonical transport headers", prefix + `,"transport":{"type":"ws","Headers":{"Host":"valid.example"}}}`},
		{"noncanonical transport path", prefix + `,"transport":{"type":"ws","Path":"/valid"}}`},
		{"noncanonical TLS", prefix + `,"TLS":{"enabled":true}}`},
		{"noncanonical TLS enabled", prefix + `,"tls":{"Enabled":true}}`},
		{"noncanonical TLS SNI", prefix + `,"tls":{"enabled":true,"Server_Name":"front.example.net"}}`},
		{"noncanonical TLS uTLS fingerprint", prefix + `,"tls":{"enabled":true,"utls":{"Fingerprint":"chrome"}}}`},
		{"noncanonical TLS reality key", prefix + `,"tls":{"enabled":true,"reality":{"Public_Key":"key"}}}`},
		{"noncanonical TLS ECH enabled", prefix + `,"tls":{"enabled":true,"ech":{"Enabled":true}}}`},
		{"noncanonical TLS ALPN", prefix + `,"tls":{"enabled":true,"ALPN":["h2"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, "8.8.8.8")
			testSelectedHostOutbound(t, m, tc.outbound)
			probes, calls := testSelectedHostReadinessProbes()
			got, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, probes)
			if err != nil || !hasReadinessReason(got, "selected_transport_unsupported") ||
				got.SelectedTransport != "" || got.EndpointKind != "" ||
				got.ActivationReady || got.GeneralHostAdmitted || len(*calls) != 0 {
				t.Fatalf("noncanonical path key reached probes or claimed support: %+v err=%v calls=%v", got, err, *calls)
			}
		})
	}
}

func TestSelectedHostCheckPreservesValidHeadersAndUnrelatedFields(t *testing.T) {
	for _, extra := range []string{
		`"transport":{"type":"ws","headers":{"hOsT":"front.example.net","X-Token":"TOKEN"}}`,
		`"transport":{"type":"http","host":["front.example.net"],"headers":{"X-Custom":["ok"]}}`,
		`"tls":{"enabled":true,"server_name":"front.example.net","alpn":["h2"]}`,
		`"tls":{"enabled":true,"utls":{"enabled":true,"fingerprint":"chrome"}}`,
		`"unrelated_opaque_metadata":{"free_form":"ok"}`,
	} {
		t.Run(extra, func(t *testing.T) {
			m := testSelectedHostReadinessManager(t, "8.8.8.8")
			testSelectedHostOutbound(t, m,
				`{"type":"vless","server":"8.8.8.8","server_port":443,"uuid":"SECRET_UUID_12345",`+extra+"}")
			probes, calls := testSelectedHostReadinessProbes()
			got, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "", 53, probes)
			if err != nil || got.TCP != "bound_tcp_connected" || (*calls)["tcp"] != 1 || got.ActivationReady {
				t.Fatalf("valid case-sensitive metadata was wrongly blocked: %+v err=%v calls=%v", got, err, *calls)
			}
		})
	}
}
