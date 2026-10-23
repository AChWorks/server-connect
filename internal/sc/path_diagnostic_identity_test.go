package sc

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// A real private Manager snapshot and real loopback HTTP proxy are exercised
// without installing/altering any host systemd unit or route. The systemd
// generation/ownership readers are the only mocked platform boundaries.
func TestPinnedDiagnosticProxyWithPrivateStateAndLifecycleDrift(t *testing.T) {
	var m *Manager
	var proxyHits atomic.Int32
	var originHits atomic.Int32
	var action atomic.Int32
	var serviceInstance atomic.Value
	serviceInstance.Store(diagnosticServiceInstance{
		PID: 2222, Invocation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer origin.Close()

	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() || r.Header.Get("Proxy-Authorization") == "" {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		proxyHits.Add(1)
		switch action.Swap(0) {
		case 1:
			// This lifecycle mutation is concurrent with the HTTP request.
			// It MUST acquire the lifecycle lock while a probe is in flight.
			err := m.withLock(func() error {
				s, err := m.load()
				if err != nil {
					return err
				}
				s.Desired = "direct"
				return m.save(s)
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		case 2:
			// Same credentials/port/selected profile, different service
			// invocation: successful HTTP cannot prove stable path.
			serviceInstance.Store(diagnosticServiceInstance{
				PID: 2222, Invocation: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			})
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxyServer.Close()

	_, portText, err := net.SplitHostPort(strings.TrimPrefix(proxyServer.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "private-manager")
	m = New(dir, "", port)
	profile := Profile{
		ID: "1111111111111111", Name: "Test profile", Kind: "sing-box-json",
		Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"203.0.113.1","server_port":443,"uuid":"11111111-1111-1111-1111-111111111111"}`),
	}
	password := strings.Repeat("a", 48)
	runtime, err := CoreConfig(profile, port, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.withLock(func() error {
		raw, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(dir, "profiles", profile.ID+".json"), raw); err != nil {
			return err
		}
		if err := put(filepath.Join(dir, "proxy-auth"), []byte(password)); err != nil {
			return err
		}
		if err := put(filepath.Join(dir, "runtime.json"), runtime); err != nil {
			return err
		}
		return m.save(State{Version: 1, Selected: profile.ID, Desired: "proxy", Port: port})
	}); err != nil {
		t.Fatal(err)
	}
	capture := func() (diagnosticProxySnapshot, error) {
		return m.captureDiagnosticProxyWithService(
			func() error { return nil },
			func() (diagnosticServiceInstance, error) {
				return serviceInstance.Load().(diagnosticServiceInstance), nil
			},
		)
	}
	targets := []string{origin.URL, strings.Replace(origin.URL, "127.0.0.1", "localhost", 1)}
	snapshot, err := capture()
	if err != nil || snapshot.identity.SelectedID != profile.ID ||
		snapshot.identity.Port != port || snapshot.proxy.User == nil {
		t.Fatalf("private selected runtime capture failed: %+v err=%v", snapshot.identity, err)
	}
	if got, ok := snapshot.proxy.User.Password(); !ok || got != password {
		t.Fatal("private selected proxy credentials were not captured")
	}
	report, err := runSelectedProxyPathDiagnostics(targets, capture)
	if err != nil || report.ReachableCount != 2 || report.Assessment != "all_targets_reachable" ||
		proxyHits.Load() != 2 || originHits.Load() != 0 {
		t.Fatalf("stable selected proxy not used for every target: %+v err=%v", report, err)
	}

	// Tampering with the desired selected runtime cannot silently prove the
	// wrong profile even if the URL, credentials and service instance are stable.
	if err := m.withLock(func() error {
		return put(filepath.Join(dir, "runtime.json"), []byte("{}"))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := capture(); err == nil {
		t.Fatal("selected profile/runtime mismatch accepted")
	}
	if err := m.withLock(func() error {
		return put(filepath.Join(dir, "runtime.json"), runtime)
	}); err != nil {
		t.Fatal(err)
	}

	action.Store(2)
	changed, err := runSelectedProxyPathDiagnostics(targets, capture)
	if ErrorCode(err) != "diagnostic_path_changed" ||
		changed.Assessment != "path_changed_unverified" || changed.ReachableCount != 0 ||
		proxyHits.Load() != 3 || originHits.Load() != 0 {
		t.Fatalf("service restart silently merged healthy samples: %+v err=%v", changed, err)
	}
	serviceInstance.Store(diagnosticServiceInstance{
		PID: 3333, Invocation: "cccccccccccccccccccccccccccccccc",
	})
	action.Store(1)
	before := proxyHits.Load()
	changed, err = runSelectedProxyPathDiagnostics(targets, capture)
	if ErrorCode(err) != "diagnostic_path_changed" || changed.ReachableCount != 0 ||
		changed.Assessment != "path_changed_unverified" || proxyHits.Load() != before+1 ||
		originHits.Load() != 0 {
		t.Fatalf("concurrent disconnect did not invalidate selected proxy report: %+v err=%v", changed, err)
	}
	// Direct/unavailable cannot borrow a successful origin or cached proxy.
	before = proxyHits.Load()
	unavailable, err := runSelectedProxyPathDiagnostics(targets, capture)
	if ErrorCode(err) != "probe_set_unreachable" || unavailable.ReachableCount != 0 ||
		unavailable.Assessment != "no_targets_reachable" ||
		proxyHits.Load() != before || originHits.Load() != 0 {
		t.Fatalf("disconnected selected proxy silently fell back: %+v err=%v", unavailable, err)
	}
	for _, sample := range unavailable.Samples {
		if sample.Status != "unavailable" || sample.ErrorCode != "proxy_unavailable" {
			t.Fatalf("missing proxy misclassified: %+v", unavailable)
		}
	}
}

func TestCaptureDiagnosticProxyRejectsUnverifiedService(t *testing.T) {
	m := New(filepath.Join(t.TempDir(), "private-manager"), "", 0)
	// Without any installed selected state, even a mocked active service is
	// never sufficient to assert a selected outbound or create HTTP traffic.
	if _, err := m.captureDiagnosticProxyWithService(
		func() error { return nil },
		func() (diagnosticServiceInstance, error) {
			return diagnosticServiceInstance{PID: 1234, Invocation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, nil
		}); err == nil {
		t.Fatal("nonexistent selected runtime accepted")
	}
	if _, err := m.captureDiagnosticProxyWithService(
		func() error { return errors.New("foreign unit") },
		func() (diagnosticServiceInstance, error) {
			return diagnosticServiceInstance{}, nil
		}); err == nil {
		t.Fatal("untrusted service accepted")
	}
}
