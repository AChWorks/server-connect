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
		dns: func(host, endpoint, resolver string, port int) (UnderlayDNSReport, error) {
			calls["dns"]++
			if host != "private.example.com" || endpoint != "8.8.8.8" || resolver != "1.1.1.1" || port != 53 {
				return UnderlayDNSReport{}, errors.New("unexpected probe target")
			}
			return UnderlayDNSReport{
				NameMatched: true, InterfaceBound: true, RouteStable: true,
				ResolverRouteDevice: "ens3",
			}, nil
		},
		tcp: func(endpoint string, port int) (UnderlayTCPReport, error) {
			calls["tcp"]++
			if endpoint != "8.8.8.8" || port != 443 {
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
				Endpoint: &HostRouteLookup{}, ManagementPeer: &HostRouteLookup{}}, nil
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

func TestSelectedHostCheckHostnamePinAndNonAdmittedReport(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, calls := testSelectedHostReadinessProbes()
	report, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ReadOnly || report.ActivationReady || report.GeneralHostAdmitted ||
		report.Mode != "selected_host_readiness" || report.EndpointKind != "hostname" ||
		report.DNS != "pinned_resolver_observed" || report.TCP != "bound_tcp_connected" ||
		report.HostRoutes != "endpoint_and_management_observed" || report.NativeNFT != "ruleset_observed" ||
		!hasReadinessReason(report, "general_host_admission_not_implemented") {
		t.Fatalf("unsafe or missing readiness result: %+v", report)
	}
	for _, name := range []string{"dns", "tcp", "routes", "nft", "proxy"} {
		if (*calls)[name] != 1 {
			t.Fatalf("%s called %d times", name, (*calls)[name])
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
	probes.dns = func(string, string, string, int) (UnderlayDNSReport, error) {
		(*calls)["dns"]++
		return UnderlayDNSReport{Outcome: "hostname_mismatch"}, errors.New("mismatch")
	}
	r, err := m.inspectSelectedSmartTUNHostWith("8.8.8.8", "198.51.100.7", "ens3", "1.1.1.1", 53, probes)
	if err != nil || r.ActivationReady || r.GeneralHostAdmitted || !hasReadinessReason(r, "endpoint_dns_unverified") ||
		r.TCP != "not_checked" || (*calls)["tcp"] != 0 {
		t.Fatalf("failed DNS unexpectedly authorized or dialed selected endpoint: %+v, %v, calls=%v", r, err, *calls)
	}
}

func TestSelectedHostCheckWrongInterfaceAndNativeNFTMissing(t *testing.T) {
	m := testSelectedHostReadinessManager(t, "private.example.com")
	probes, _ := testSelectedHostReadinessProbes()
	probes.dns = func(string, string, string, int) (UnderlayDNSReport, error) {
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
