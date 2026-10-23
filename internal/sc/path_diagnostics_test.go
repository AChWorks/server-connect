package sc

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPathDiagnosticsPreflightRejectsWithoutNetworkProbe(t *testing.T) {
	validA := "https://one.example/health"
	validB := "https://two.example/health"
	tests := []struct {
		name, path string
		targets    []string
	}{
		{"wrong_path", "vpn", []string{validA, validB}},
		{"missing_target", "proxy", []string{validA}},
		{"no_targets", "proxy", nil},
		{"five_targets", "direct", []string{validA, validB, "https://three.example", "https://four.example", "https://five.example"}},
		{"same_host_case", "proxy", []string{validA, "https://ONE.EXAMPLE/another"}},
		{"same_host_different_ports", "proxy", []string{"https://one.example:443", "http://one.example:80"}},
		{"ftp_url", "direct", []string{"ftp://one.example", validB}},
		{"password_in_url", "proxy", []string{"https://username:secret-token@one.example/test", validB}},
		{"fragment_url", "proxy", []string{"https://one.example/test#secret-token", validB}},
		{"scheme_relative", "proxy", []string{"//one.example/path", validB}},
		{"oversize", "direct", []string{"https://one.example/" + strings.Repeat("z", 2200), validB}},
		{"newline", "proxy", []string{"https://one.example/\nunsafe", validB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			result, err := runPathDiagnostics(tt.path, tt.targets, func(string) (ProbeResult, error) {
				calls++
				return ProbeResult{Path: tt.path, Code: 200, Result: "reachable"}, nil
			})
			if ErrorCode(err) != "invalid_arguments" || calls != 0 || result.Assessment != "not_tested" ||
				result.ActivationReady || result.TunnelHealthVerified || result.FallbackAttempted {
				t.Fatalf("unsupported input triggered a network action or readiness: %+v error=%v calls=%d", result, err, calls)
			}
		})
	}
}

func TestPathDiagnosticsAggregationNeverMistakesPartialForHealthy(t *testing.T) {
	targets := []string{"https://one.example", "https://two.example"}
	for _, tt := range []struct {
		name                 string
		resultOne, resultTwo ProbeResult
		errOne, errTwo       error
		assessment, fault    string
		healthy              int
	}{
		{"all_reachable", ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, ProbeResult{Path: "proxy", Code: 204, Result: "reachable"}, nil, nil, "all_targets_reachable", "", 2},
		{"partial_http_502", ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, ProbeResult{Path: "proxy", Code: 502, Result: "http_error"}, nil, Fault("probe_http", "bad response"), "mixed_results", "probe_set_partial", 1},
		{"partial_dns", ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, ProbeResult{Path: "proxy", Result: "failed"}, nil, Fault("probe_dns", "dns failed"), "mixed_results", "probe_set_partial", 1},
		{"redirect_is_not_content_proof", ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, ProbeResult{Path: "proxy", Code: 302, Result: "reachable"}, nil, nil, "mixed_results", "probe_set_partial", 1},
		{"both_unavailable", ProbeResult{Path: "proxy", Result: "unavailable"}, ProbeResult{Path: "proxy", Result: "unavailable"}, Fault("proxy_unavailable", "proxy unavailable"), Fault("proxy_unavailable", "proxy unavailable"), "no_targets_reachable", "probe_set_unreachable", 0},
		{"wrong_path_is_not_health", ProbeResult{Path: "direct", Code: 200, Result: "reachable"}, ProbeResult{Path: "direct", Code: 200, Result: "reachable"}, nil, nil, "no_targets_reachable", "probe_set_unreachable", 0},
		{"falsified_http_status", ProbeResult{Path: "proxy", Code: 502, Result: "reachable"}, ProbeResult{Path: "proxy", Code: 200, Result: "reachable"}, nil, nil, "mixed_results", "probe_set_partial", 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			index := 0
			calls := 0
			result, err := runPathDiagnostics("proxy", targets, func(string) (ProbeResult, error) {
				calls++
				defer func() { index++ }()
				if index == 0 {
					return tt.resultOne, tt.errOne
				}
				return tt.resultTwo, tt.errTwo
			})
			if ErrorCode(err) != tt.fault || result.Assessment != tt.assessment || result.ReachableCount != tt.healthy ||
				result.FailedCount != len(targets)-tt.healthy || len(result.Samples) != len(targets) || calls != len(targets) ||
				!result.HostNetworkReadOnly || result.FallbackAttempted || result.ActivationReady || result.TunnelHealthVerified {
				t.Fatalf("incorrect diagnostic classification %+v err=%v calls=%d", result, err, calls)
			}
			if result.Samples[0].Index != 0 || result.Samples[1].Index != 1 {
				t.Fatalf("target indices lost %+v", result.Samples)
			}
		})
	}
}

func TestPathDiagnosticsNeverEchoesTargetCredentials(t *testing.T) {
	inputs := []string{
		"https://one.example/secret-token?token=123",
		"https://two.example/personal/path?key=topsecret",
	}
	r, err := runPathDiagnostics("proxy", inputs, func(string) (ProbeResult, error) {
		return ProbeResult{Path: "proxy", Result: "failed"}, Fault("probe_dns", "resolution failed")
	})
	if ErrorCode(err) != "probe_set_unreachable" {
		t.Fatal(err)
	}
	jsonData, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret-token", "topsecret", "one.example", "two.example", "personal"} {
		if strings.Contains(string(jsonData), forbidden) {
			t.Fatalf("sensitive target leaked: %s", forbidden)
		}
	}
}

func TestPathDiagnosticsDirectLiveHTTPAndNoFallbackToAnotherPath(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer good.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
	}))
	defer bad.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(bad.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	badDistinct := "http://localhost:" + port + "/broken"
	m := New(t.TempDir(), "", 0)
	inputs := []string{good.URL, badDistinct}
	mixed, err := m.DiagnosePath("direct", inputs)
	if ErrorCode(err) != "probe_set_partial" || mixed.Assessment != "mixed_results" ||
		mixed.ReachableCount != 1 || mixed.Samples[1].HTTPStatus != 502 || mixed.Samples[1].ErrorCode != "probe_http" {
		t.Fatalf("HTTP request disagreement not attributed: %+v err=%v", mixed, err)
	}
	// Even when both hosts can be reached directly, an unavailable selected
	// proxy cannot borrow Direct success as evidence of proxy health.
	proxy, err := m.DiagnosePath("proxy", inputs)
	if err == nil || proxy.ReachableCount != 0 || proxy.Assessment != "no_targets_reachable" ||
		proxy.FallbackAttempted || proxy.TunnelHealthVerified {
		t.Fatalf("dead/uninstalled proxy silently passed via Direct: %+v err=%v", proxy, err)
	}
}
