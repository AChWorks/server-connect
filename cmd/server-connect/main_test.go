package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestUntrustedUnitFlagRefusedWithoutServiceOperation(t *testing.T) {
	for _, args := range [][]string{
		{"--unit", "ssh.service", "disconnect"},
		{"--json", "--unit", "cron.service", "disconnect"},
	} {
		jsonOut, manager, _, err := parseOpts(args)
		if err == nil || manager != nil {
			t.Fatalf("an arbitrary service must not enter lifecycle: %#v", args)
		}
		if !strings.Contains(err.Error(), "invalid or unsupported") || sc.ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("bad flag classification: %v", err)
		}
		if len(args) > 0 && args[0] == "--json" && !jsonOut {
			t.Fatal("--json intent lost during flag error")
		}
	}
}

func TestInputSourceNeverEchoesCredentialURIOrFilename(t *testing.T) {
	sensitive := "vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@server.invalid:443?type=ws"
	_, err := readInput(sensitive)
	if err == nil || strings.Contains(err.Error(), "c2902f3a") || strings.Contains(err.Error(), "server.invalid") {
		t.Fatalf("URI leaked through readInput: %v", err)
	}
	if sc.ErrorCode(err) != "invalid_input" {
		t.Fatalf("wrong safe class: %s", sc.ErrorCode(err))
	}
	_, err = readInput("/nonexistent/secret-account-token")
	if err == nil || strings.Contains(err.Error(), "secret-account-token") || sc.ErrorCode(err) != "file_not_found" {
		t.Fatalf("file path leakage or class: %v", err)
	}
}

func TestJSONErrorEnvelopeContainsSafeCategory(t *testing.T) {
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = old; reader.Close() }()
	if exit := output(true, map[string]any{"path": "proxy"}, sc.Fault("probe_http", "upstream returned unhealthy response")); exit != 1 {
		t.Fatalf("expected nonzero exit %d", exit)
	}
	writer.Close()
	var got struct {
		OK    bool           `json:"ok"`
		Data  map[string]any `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err = json.NewDecoder(reader).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.OK || got.Error.Code != "probe_http" || got.Data["path"] != "proxy" {
		t.Fatalf("failure envelope invalid: %+v", got)
	}
}

func TestMenuAptUpdateRequiresExplicitConfirmation(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write([]byte("9\nNO\n0\n")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old; input.Close() }()
	if code := menu(manager); code != 0 {
		t.Fatalf("menu exit: %d", code)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("canceled APT action unexpectedly touched protected product state")
	}
}

func TestUnknownCommandNeverEchoesPastedBearerURI(t *testing.T) {
	secret := "vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@secret.invalid:443?type=tcp"
	m := sc.New(t.TempDir(), "", 0)
	for _, jsonMode := range []bool{true, false} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		oldOut, oldErr := os.Stdout, os.Stderr
		os.Stdout, os.Stderr = writer, writer
		exit := run(jsonMode, m, []string{secret})
		writer.Close()
		os.Stdout, os.Stderr = oldOut, oldErr
		out, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		if exit == 0 || strings.Contains(string(out), "c2902f3a") || strings.Contains(string(out), "secret.invalid") {
			t.Fatalf("unknown-command secret exposure or success: code=%d", exit)
		}
		if jsonMode && !strings.Contains(string(out), "unknown_command") {
			t.Fatal("machine-readable error code missing")
		}
	}
}

func TestUnderlayExplicitEmptyHostnameCannotBypassValidation(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeRead.Close()
	oldOut := os.Stdout
	os.Stdout = pipeWrite
	exit := run(true, manager, []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "443", "--hostname="})
	_ = pipeWrite.Close()
	os.Stdout = oldOut
	out, err := io.ReadAll(pipeRead)
	if err != nil {
		t.Fatal(err)
	}
	if exit == 0 {
		t.Fatal("explicit empty hostname bypassed required DNS validation")
	}
	var response struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("malformed JSON: %s (%v)", out, err)
	}
	if response.OK || response.Error.Code != "invalid_arguments" {
		t.Fatalf("empty hostname did not fail safely: %s", out)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid hostname unexpectedly modified manager state")
	}
}

func TestUnderlayDNSCLIRejectsMissingAndAmbiguousInputs(t *testing.T) {
	for _, args := range [][]string{
		{"underlay-dns", "--hostname", "node.example.test", "--endpoint", "198.51.100.17"},
		{"underlay-dns", "--hostname", "node.example.test", "--endpoint", "198.51.100.17", "--resolver", "dns.example.test"},
		{"underlay-dns", "--hostname", "node.example.test", "--endpoint", "198.51.100.17", "--resolver", "127.0.0.1", "--resolver-port", "0"},
		{"underlay-dns", "--hostname", "", "--endpoint", "198.51.100.17", "--resolver", "127.0.0.1"},
		{"underlay-dns", "--hostname", "node.example.test", "--endpoint", "198.51.100.17", "--resolver", "127.0.0.1", "extra"},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		exit := run(true, sc.New(t.TempDir(), "", 0), args)
		_ = writer.Close()
		os.Stdout = old
		var response struct {
			OK    bool            `json:"ok"`
			Data  json.RawMessage `json:"data"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		err = json.NewDecoder(reader).Decode(&response)
		_ = reader.Close()
		if err != nil || exit == 0 || response.OK || response.Error.Code != "invalid_arguments" || len(response.Data) != 0 {
			t.Fatalf("invalid explicit resolver input emitted fake report: %v exit=%d response=%+v err=%v", args, exit, response, err)
		}
	}
}

// PRE-validation failures have no structured route observations: omit data
// instead of serializing a zero-value report with read_only:false.
func TestUnderlayTCPInvalidArgumentsOmitDiagnosticData(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing_endpoint", []string{"underlay-tcp", "--port", "443"}},
		{"malformed_endpoint", []string{"underlay-tcp", "--endpoint", "fake.remote.invalid", "--port", "443"}},
		{"zero_port", []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "0"}},
		{"oversized_port", []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "65536"}},
		{"hostname_syntax", []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "443", "--hostname", "invalid@@name"}},
		{"empty_hostname", []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "443", "--hostname="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := os.Stdout
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = writer
			exit := run(true, m, tc.args)
			_ = writer.Close()
			os.Stdout = old
			defer reader.Close()
			var got struct {
				OK    bool            `json:"ok"`
				Data  json.RawMessage `json:"data"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.NewDecoder(reader).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if exit == 0 || got.OK || got.Error.Code != "invalid_arguments" || len(got.Data) != 0 {
				t.Fatalf("invalid input emitted fake route evidence: %+v exit=%d", got, exit)
			}
			if strings.Contains(got.Error.Message, "fake.remote.invalid") || strings.Contains(got.Error.Message, "invalid@@name") {
				t.Fatal("input echoed into a machine-visible failure")
			}
		})
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid underlay arguments touched protected state")
	}
}

func TestUnderlayTCPValidArgumentsRetainSafePartialFailureReport(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	// This is a syntactically valid request, even on hosts without iproute2.
	exit := run(true, m, []string{"underlay-tcp", "--endpoint", "127.0.0.1", "--port", "1"})
	_ = writer.Close()
	os.Stdout = old
	defer reader.Close()
	var got struct {
		OK   bool `json:"ok"`
		Data struct {
			Mode                 string `json:"mode"`
			ReadOnly             bool   `json:"read_only"`
			ActivationReady      bool   `json:"activation_ready"`
			DNSBootstrapVerified bool   `json:"dns_bootstrap_verified"`
			Outcome              string `json:"outcome"`
		} `json:"data"`
		Error *apiError `json:"error"`
	}
	if err := json.NewDecoder(reader).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if exit == 0 || got.OK || got.Data.Mode != "underlay_tcp_diagnostic" ||
		!got.Data.ReadOnly || got.Data.ActivationReady || got.Data.DNSBootstrapVerified ||
		got.Data.Outcome == "" || got.Error == nil {
		t.Fatalf("runtime failure lost required truthful safety evidence: %+v exit=%d", got, exit)
	}
}

// After valid underlay-dns arguments, even a refused DNS resolver retains
// truthful partial safety evidence and a nonzero exit / structured error.
func TestUnderlayDNSValidArgumentsRetainPartialFailure(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	exit := run(true, m, []string{"underlay-dns", "--hostname", "node.example.test",
		"--endpoint", "198.51.100.9", "--resolver", "127.0.0.1", "--resolver-port", "1"})
	_ = writer.Close()
	os.Stdout = old
	defer reader.Close()
	var result struct {
		OK   bool `json:"ok"`
		Data struct {
			Mode                 string `json:"mode"`
			ReadOnly             bool   `json:"read_only"`
			ActivationReady      bool   `json:"activation_ready"`
			DNSBootstrapVerified bool   `json:"dns_bootstrap_verified"`
			Outcome              string `json:"outcome"`
		} `json:"data"`
		Error *apiError `json:"error"`
	}
	if err := json.NewDecoder(reader).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if exit == 0 || result.OK || result.Error == nil ||
		result.Data.Mode != "explicit_resolver_diagnostic" || !result.Data.ReadOnly ||
		result.Data.ActivationReady || result.Data.DNSBootstrapVerified || result.Data.Outcome == "" {
		t.Fatalf("DNS runtime error lost partial safety report: %+v exit=%d", result, exit)
	}
}

func TestHostDriftCLIRejectsBaselineBeforeNetworkWithoutFakeData(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	secretPath := filepath.Join(t.TempDir(), "secret-private-host-snapshot.json")
	for _, args := range [][]string{
		{"host-drift"},
		{"host-drift", "--baseline", secretPath},
		{"host-drift", "--baseline", "-", "unexpected"},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		exit := run(true, m, args)
		_ = writer.Close()
		os.Stdout = old
		var response struct {
			OK    bool            `json:"ok"`
			Data  json.RawMessage `json:"data"`
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		err = json.NewDecoder(reader).Decode(&response)
		_ = reader.Close()
		if err != nil || exit == 0 || response.OK || len(response.Data) > 0 ||
			(response.Error.Code != "invalid_arguments" && response.Error.Code != "invalid_baseline") ||
			strings.Contains(response.Error.Message, "secret-private-host") {
			t.Fatalf("invalid baseline output unsafe: args=%q response=%+v err=%v exit=%d", args, response, err, exit)
		}
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid host-drift command touched protected product state")
	}
}

func TestHostDriftCLIRoundtripRealHostPreflight(t *testing.T) {
	if _, err := os.Stat("/usr/bin/ip"); err != nil {
		t.Skip("native iproute2 is installed in later Debian 13 CI stage")
	}
	m := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	capture := func(args ...string) (int, []byte) {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		code := run(true, m, args)
		_ = writer.Close()
		os.Stdout = old
		data, err := io.ReadAll(reader)
		_ = reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		return code, data
	}
	code, baseline := capture("host-preflight", "--endpoint", "127.0.0.1", "--management-peer", "127.0.0.2")
	if code != 0 {
		t.Fatalf("baseline host preflight unavailable: %s", baseline)
	}
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, baseline, 0600); err != nil {
		t.Fatal(err)
	}
	code, out := capture("host-drift", "--baseline", path)
	var report struct {
		OK   bool `json:"ok"`
		Data struct {
			Mode            string `json:"mode"`
			ReadOnly        bool   `json:"read_only"`
			ActivationReady bool   `json:"activation_ready"`
			SnapshotAtomic  bool   `json:"snapshot_atomic"`
			CurrentObserved bool   `json:"current_observed"`
			Changed         bool   `json:"changed"`
			Outcome         string `json:"outcome"`
			Components      []struct {
				Name    string `json:"name"`
				Changed bool   `json:"changed"`
			} `json:"components"`
		} `json:"data"`
		Error *apiError `json:"error"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if code != 0 || !report.OK || report.Error != nil ||
		report.Data.Mode != "host_drift_diagnostic" || !report.Data.ReadOnly ||
		report.Data.ActivationReady || report.Data.SnapshotAtomic ||
		!report.Data.CurrentObserved || report.Data.Changed || len(report.Data.Components) != 7 {
		t.Fatalf("actual CLI host drift roundtrip inaccurate: code=%d report=%s", code, out)
	}

	// Change the saved baseline (not a real route). Detect the precise
	// component without ever mutating host networking.
	var fixture struct {
		OK   bool `json:"ok"`
		Data struct {
			IPv4Routes []any `json:"ipv4_routes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(baseline, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.Data.IPv4Routes = append(fixture.Data.IPv4Routes,
		map[string]string{"dst": "198.51.100.0/24", "dev": "synthetic-foreign-change"})
	newJSON, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	// Replace only the snapshot field to retain the other genuine observations.
	var raw map[string]any
	if err := json.Unmarshal(baseline, &raw); err != nil {
		t.Fatal(err)
	}
	var changed map[string]any
	if err := json.Unmarshal(newJSON, &changed); err != nil {
		t.Fatal(err)
	}
	raw["data"].(map[string]any)["ipv4_routes"] = changed["data"].(map[string]any)["ipv4_routes"]
	payload, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	code, out = capture("host-drift", "--baseline", path)
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatal(err)
	}
	if code == 0 || report.OK || report.Error == nil ||
		report.Error.Code != "host_drift_detected" ||
		!report.Data.CurrentObserved || !report.Data.Changed ||
		!report.Data.ReadOnly || report.Data.ActivationReady || report.Data.SnapshotAtomic {
		t.Fatalf("synthetic drift did not fail closed: code=%d response=%s", code, out)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("host-drift CLI unexpectedly wrote manager state")
	}
}

// A bad or canceled baseline via the interactive path must remain as safe
// as the structured CLI: never initialize private manager state or edit hosts.
func TestMenuHostDriftInvalidAndCanceledInputDoesNotMutateState(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "manager"), "", 0)
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipeRead.Close()
	_, _ = pipeWrite.Write([]byte("13\n\n13\n/nonexistent/private.json\n0\n"))
	_ = pipeWrite.Close()
	old := os.Stdin
	os.Stdin = pipeRead
	defer func() { os.Stdin = old }()
	if code := menu(m); code != 0 {
		t.Fatalf("unexpected menu exit: %d", code)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("menu diagnostic unexpectedly created manager state")
	}
}
