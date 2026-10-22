package sc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestProbeHTTPPathUsesOnlyExplicitSelectedProxy(t *testing.T) {
	originHits := atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()
	proxyHits := atomic.Int32{}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.Header.Get("Proxy-Authorization") == "" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		proxyHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL.User = url.UserPassword("sc", "private-test-pass")
	selected, err := probeHTTPPath("proxy", origin.URL, proxyURL)
	if err != nil || selected.Path != "proxy" || selected.Code != 204 ||
		selected.Result != "reachable" || proxyHits.Load() != 1 || originHits.Load() != 0 {
		t.Fatalf("explicit proxy traffic did not remain selected: %+v err=%v", selected, err)
	}
	// Direct can reach the host but cannot turn a selected proxy failure
	// into a positive selected-path result.
	direct, err := probeHTTPPath("direct", origin.URL, nil)
	if ErrorCode(err) != "probe_http" || direct.Code != 503 || originHits.Load() != 1 {
		t.Fatalf("Direct diagnostic unexpected: %+v err=%v", direct, err)
	}
	proxy.Close()
	dead, err := probeHTTPPath("proxy", origin.URL, proxyURL)
	if err == nil || dead.Result == "reachable" || originHits.Load() != 1 {
		t.Fatalf("dead proxy silently borrowed the functioning Direct path: %+v err=%v", dead, err)
	}
	missing, err := probeHTTPPath("proxy", origin.URL, nil)
	if ErrorCode(err) != "proxy_unavailable" || missing.Result != "unavailable" {
		t.Fatalf("missing proxy was not fail-closed: %+v err=%v", missing, err)
	}
}

func TestProbeHTTPPathNeverFollowsOriginRedirectOrDisablesTLSValidation(t *testing.T) {
	redirectedHits := atomic.Int32{}
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	redirectSource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	defer redirectSource.Close()
	result, err := probeHTTPPath("direct", redirectSource.URL, nil)
	if err != nil || result.Code != 302 || redirectedHits.Load() != 0 {
		t.Fatalf("redirect was silently followed: %+v err=%v", result, err)
	}
	// A redirect alone cannot establish independent HTTP content health.
	summary, err := runPathDiagnostics("direct",
		[]string{redirectSource.URL, strings.Replace(redirectTarget.URL, "127.0.0.1", "localhost", 1)},
		func(target string) (ProbeResult, error) { return probeHTTPPath("direct", target, nil) })
	if ErrorCode(err) != "probe_set_partial" || summary.ReachableCount != 1 ||
		summary.Samples[0].ErrorCode != "probe_redirect_unverified" {
		t.Fatalf("302 falsely counted as verified content: %+v err=%v", summary, err)
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tlsServer.Close()
	result, err = probeHTTPPath("direct", tlsServer.URL, nil)
	if ErrorCode(err) != "probe_tls" || result.Result == "reachable" {
		t.Fatalf("untrusted TLS certificate was accepted: %+v err=%v", result, err)
	}
}
