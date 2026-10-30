package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestInstallerTargetCheckRejectsOverridesWithoutState(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "state"), "", 0)
	old := os.Stdout
	defer func() { os.Stdout = old }()
	for _, args := range [][]string{
		{"installer-check-target"},
		{"installer-check-target", "--manifest", ""},
		{"installer-check-target", "--manifest", "/private/manifest.json", "--target", "debian-12-amd64"},
		{"installer-check-target", "--manifest", "/private/manifest.json", "--os-release", "/private/os-release"},
		{"installer-check-target", "--manifest", "/private/manifest.json", "extra"},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdout = writer
		code := run(true, manager, args)
		writer.Close()
		os.Stdout = old
		var result envelope
		err = json.NewDecoder(reader).Decode(&result)
		reader.Close()
		if err != nil || code != 1 || result.OK || result.Error == nil || result.Error.Code != "invalid_arguments" {
			t.Fatalf("installer input/host override was not rejected: %v, %+v, %v", args, result, err)
		}
		if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
			t.Fatal("installer target refusal initialized product state")
		}
	}
}

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

// Retired per-process diagnostics must not silently return as routing controls.
func TestRetiredWorkloadObserveIsNotAnActiveCommand(t *testing.T) {
	store := filepath.Join(t.TempDir(), "state")
	manager := sc.New(store, "", 0)
	if code := run(true, manager, []string{"workload-observe", "--pid", "2", "--descendants", "--sockets"}); code == 0 {
		t.Fatal("retired process-based diagnostic unexpectedly accepted")
	}
	if _, err := os.Stat(store); !os.IsNotExist(err) {
		t.Fatal("unsupported per-process command touched product state")
	}
}

func TestDiagnosePathCLIHonorsErrorsAndRedactsTargets(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer healthy.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer broken.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(broken.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	urls := []string{healthy.URL + "/secret-local-path?token=secret-token", "http://localhost:" + port + "/private/report"}
	m := sc.New(filepath.Join(t.TempDir(), "missing-state"), "", 0)
	runAndCapture := func(args []string) (int, []byte) {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		code := run(true, m, args)
		writer.Close()
		os.Stdout = old
		out, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		return code, out
	}
	args := []string{"diagnose-path", "--via", "direct", "--url", urls[0], "--url", urls[1]}
	code, out := runAndCapture(args)
	if code != 1 || strings.Contains(string(out), "secret-token") ||
		strings.Contains(string(out), "private/report") {
		t.Fatalf("diagnostic failure or secret reflection: exit=%d", code)
	}
	var envelope struct {
		OK   bool `json:"ok"`
		Data struct {
			Assessment     string `json:"assessment"`
			Path           string `json:"path"`
			ReachableCount int    `json:"reachable_count"`
			FailedCount    int    `json:"failed_count"`
			Samples        []struct {
				HTTPStatus int `json:"http_status"`
			} `json:"samples"`
		} `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error.Code != "probe_set_partial" || envelope.Data.Assessment != "mixed_results" ||
		envelope.Data.Path != "direct" || envelope.Data.ReachableCount != 1 || envelope.Data.FailedCount != 1 ||
		len(envelope.Data.Samples) != 2 || envelope.Data.Samples[1].HTTPStatus != 502 {
		t.Fatalf("incorrect machine status: %+v", envelope)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatalf("Direct diagnostics unexpectedly created a private state directory: %v", err)
	}
	_, healthyPort, err := net.SplitHostPort(strings.TrimPrefix(healthy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	code, out = runAndCapture([]string{"diagnose-path", "--via", "direct",
		"--url", healthy.URL, "--url", "http://localhost:" + healthyPort + "/healthy"})
	if code != 0 || !strings.Contains(string(out), `"ok":true`) ||
		!strings.Contains(string(out), "all_targets_reachable") {
		t.Fatalf("both successful direct responses were incorrectly rejected: exit=%d output=%s", code, out)
	}
	// Proxy mode must never claim a direct success when no owned proxy exists.
	args[2] = "proxy"
	code, out = runAndCapture(args)
	if code != 1 || !strings.Contains(string(out), "probe_set_unreachable") ||
		!strings.Contains(string(out), "no_targets_reachable") {
		t.Fatalf("unavailable Proxy incorrectly used Direct: code=%d output=%s", code, out)
	}
	// A URL with inline credentials must be refused before any HTTP request.
	code, out = runAndCapture([]string{"diagnose-path", "--via", "direct",
		"--url", "https://operator:secret-token@one.example/api", "--url", "https://two.example"})
	if code != 1 || !strings.Contains(string(out), "invalid_arguments") || strings.Contains(string(out), "secret-token") {
		t.Fatalf("unsafe URI accepted or reflected: code=%d", code)
	}
}

func TestDiagnosticPathDriftJSONExitAndSanitization(t *testing.T) {
	report := sc.PathDiagnostics{
		Path: "proxy", Assessment: "path_changed_unverified",
		TargetCount: 2, ReachableCount: 0, FailedCount: 2,
		Samples: []sc.PathDiagnosticTarget{
			{Index: 0, Status: "unverified", ErrorCode: "diagnostic_path_changed"},
			{Index: 1, Status: "unverified", ErrorCode: "diagnostic_path_changed"},
		},
		HostNetworkReadOnly: true,
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	exit := output(true, report, sc.Fault("diagnostic_path_changed", "selected proxy identity changed; aggregate path evidence is unverified"))
	writer.Close()
	os.Stdout = old
	raw, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		OK    bool               `json:"ok"`
		Data  sc.PathDiagnostics `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if exit != 1 || result.OK || result.Error.Code != "diagnostic_path_changed" ||
		result.Data.Assessment != "path_changed_unverified" || result.Data.ReachableCount != 0 ||
		len(result.Data.Samples) != 2 || result.Data.Samples[0].Status != "unverified" {
		t.Fatalf("path drift must be a machine failure with safe samples: %+v", result)
	}
	for _, forbidden := range []string{"password", "https://", "private-token"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("unexpected private path information in JSON")
		}
	}
}

func TestSelectivePlanRejectsUnsafeCLIWithoutProductState(t *testing.T) {
	tests := [][]string{
		{"selective-plan"},
		{"selective-plan", "--endpoint", "example.org", "--management-peer", "9.9.9.9",
			"--tunnel-if", "scdemo0", "--destination", "8.8.8.0/24"},
		{"selective-plan", "--endpoint", "1.1.1.1", "--management-peer", "9.9.9.9",
			"--tunnel-if", "lo", "--destination", "0.0.0.0/0"},
		{"selective-plan", "--endpoint", "1.1.1.1", "--management-peer", "9.9.9.9",
			"--tunnel-if", "scdemo0", "--destination", "8.8.8.0/24", "--surprise"},
	}
	for _, args := range tests {
		m := sc.New(filepath.Join(t.TempDir(), "missing-product-state"), "", 0)
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		exit := run(true, m, args)
		writer.Close()
		os.Stdout = old
		body, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || exit != 1 {
			t.Fatalf("unexpected exit/error for %v: exit=%d err=%v", args, exit, err)
		}
		var out struct {
			OK    bool            `json:"ok"`
			Data  json.RawMessage `json:"data"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &out); err != nil ||
			out.OK || len(out.Data) != 0 || out.Error.Code != "invalid_arguments" {
			t.Fatalf("invalid plan escaped validation: %s err=%v", body, err)
		}
		if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
			t.Fatal("invalid preview unexpectedly created product state")
		}
	}
}

func TestSelectivePlanMenuRejectsEmptyInputWithoutTouchingHost(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "missing-product-state"), "", 0)
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(strings.Join([]string{"12", "", "", "", "", "0", ""}, string(rune(10))))); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old; input.Close() }()
	if code := menu(manager); code != 0 {
		t.Fatalf("menu exit=%d", code)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("preview menu unexpectedly wrote product state")
	}
}

func TestDistinctMenuOptionsAfterPathDiagnosticIntegration(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "missing-product-state"), "", 0)
	input, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Option 11 remains the previously merged diagnostic, while option 12
	// is the new read-only selective planner. Neither accepts empty inputs.
	lines := []string{"11", "", "", "2", "12", "", "", "", "", "0", ""}
	if _, err := inputWriter.Write([]byte(strings.Join(lines, "\n"))); err != nil {
		t.Fatal(err)
	}
	inputWriter.Close()
	reader, outputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, outputWriter
	defer func() { os.Stdin, os.Stdout = oldIn, oldOut; input.Close(); reader.Close() }()
	code := menu(manager)
	outputWriter.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || !strings.Contains(string(raw), "First independent HTTP(S) target:") ||
		!strings.Contains(string(raw), "Pinned VPN endpoint literal IP:") ||
		!strings.Contains(string(raw), "11 Path Diagnostics  12 Selective Plan") {
		t.Fatalf("interactive option 11/12 reconciliation failed: exit=%d", code)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid interactive diagnostics/planner unexpectedly created product state")
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

func TestUnderlayTCPMenu13PreservesExistingOptions(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "missing-product-state"), "", 0)
	in, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// 13: literal IP, invalid port and omitted hostname; no TCP socket
	// is opened and no manager state is created. Keep 11/12 intact.
	if _, err := writer.Write([]byte("13\n127.0.0.1\n0\n\n0\n")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	out, capture, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = in, capture
	code := menu(manager)
	capture.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	defer in.Close()
	raw, err := io.ReadAll(out)
	out.Close()
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 ||
		!strings.Contains(string(raw), "11 Path Diagnostics  12 Selective Plan  13 Underlay TCP") ||
		!strings.Contains(string(raw), "Literal TCP endpoint IP (no DNS):") ||
		!strings.Contains(string(raw), "Endpoint TCP port:") {
		t.Fatalf("distinct option 13 not wired: code=%d output=%s", code, raw)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid underlay menu unexpectedly created product state")
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

func TestUnderlayDNSMenu14RetainsOtherDiagnostics(t *testing.T) {
	manager := sc.New(filepath.Join(t.TempDir(), "missing-product-state"), "", 0)
	in, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Option 14 is invalid and does not dial or create persistent state.
	if _, err := writer.Write([]byte("14\n\n\n\n0\n")); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	out, capture, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = in, capture
	exit := menu(manager)
	capture.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	defer in.Close()
	content, err := io.ReadAll(out)
	out.Close()
	if err != nil {
		t.Fatal(err)
	}
	if exit != 0 ||
		!strings.Contains(string(content), "11 Path Diagnostics  12 Selective Plan  13 Underlay TCP  14 Underlay DNS") ||
		!strings.Contains(string(content), "Endpoint DNS hostname:") ||
		!strings.Contains(string(content), "Pinned endpoint IP:") ||
		!strings.Contains(string(content), "Explicit resolver IP") {
		t.Fatalf("DNS option 14 collides or is missing: exit=%d", exit)
	}
	if _, err := os.Stat(manager.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid underlay DNS menu created product state")
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
	if bytes.Contains(out, []byte("127.0.0.1")) || bytes.Contains(out, []byte("127.0.0.2")) ||
		bytes.Contains(out, []byte(`"endpoint"`)) || bytes.Contains(out, []byte(`"management_peer"`)) {
		t.Fatalf("private baseline targets leaked in matching JSON report: %s", out)
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
	if bytes.Contains(out, []byte("127.0.0.1")) || bytes.Contains(out, []byte("127.0.0.2")) {
		t.Fatalf("private baseline targets leaked in drift JSON report: %s", out)
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
	_, _ = pipeWrite.Write([]byte("15\n\n15\n/nonexistent/private.json\n0\n"))
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

func hostDriftCapturedOutput(t *testing.T, invoke func() int) (int, string, string) {
	t.Helper()
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	code := invoke()
	_ = outW.Close()
	_ = errW.Close()
	stdout, e1 := io.ReadAll(outR)
	stderr, e2 := io.ReadAll(errR)
	_ = outR.Close()
	_ = errR.Close()
	if e1 != nil || e2 != nil {
		t.Fatalf("output read: %v / %v", e1, e2)
	}
	return code, string(stdout), string(stderr)
}

func hostDriftRealChangedBaseline(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/usr/bin/ip"); err != nil {
		t.Skip("native Debian 13 iproute2 tests run in CI's native stage")
	}
	snapshot, err := sc.InspectHostRoutes("127.0.0.1", "127.0.0.2")
	if err != nil {
		t.Skipf("root-owned trusted iproute2 unavailable: %v", err)
	}
	var rows []json.RawMessage
	if err := json.Unmarshal(snapshot.IPv4Routes, &rows); err != nil {
		t.Fatal(err)
	}
	rows = append(rows, json.RawMessage(`{"dst":"203.0.113.0/24","dev":"synthetic-baseline-only"}`))
	snapshot.IPv4Routes, err = json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(struct {
		OK   bool             `json:"ok"`
		Data sc.HostPreflight `json:"data"`
	}{OK: true, Data: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private-host-drift-fingerprint-test.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hostDriftNetworkSnapshot(t *testing.T) []byte {
	t.Helper()
	var state bytes.Buffer
	for _, args := range [][]string{
		{"-j", "-4", "route", "show", "table", "all"},
		{"-j", "-6", "route", "show", "table", "all"},
		{"-j", "-4", "rule", "show"},
		{"-j", "-6", "rule", "show"},
	} {
		bytes, err := exec.Command("/usr/bin/ip", args...).Output()
		if err != nil {
			t.Fatal(err)
		}
		state.Write(bytes)
	}
	return state.Bytes()
}

func assertHostDriftEvidenceVisible(t *testing.T, stdout, stderr, path string) {
	t.Helper()
	for _, term := range []string{
		`"mode": "host_drift_diagnostic"`,
		`"read_only": true`,
		`"activation_ready": false`,
		`"snapshot_atomic": false`,
		`"current_observed": true`,
		`"changed": true`,
		`"name": "ipv4_routes"`,
		`"baseline_sha256"`,
		`"observed_sha256"`,
		`"outcome": "observations_changed"`,
	} {
		if !strings.Contains(stdout, term) {
			t.Errorf("missing visible diagnostic %s: %s", term, stdout)
		}
	}
	if !strings.Contains(stderr, "host_drift_detected") {
		t.Errorf("non-JSON operator output lacks error class: %s", stderr)
	}
	if strings.Contains(stdout, path) || strings.Contains(stderr, path) ||
		strings.Contains(stdout, "127.0.0.1") || strings.Contains(stdout, "127.0.0.2") ||
		strings.Contains(stderr, "127.0.0.1") || strings.Contains(stderr, "127.0.0.2") ||
		strings.Contains(stdout, "synthetic-baseline-only") {
		t.Fatal("private baseline filename/content leaked to operator output")
	}
}

func TestHostDriftCLINonJSONFailureShowsChangedComponent(t *testing.T) {
	path := hostDriftRealChangedBaseline(t)
	m := sc.New(filepath.Join(t.TempDir(), "manager"), "", 0)
	before := hostDriftNetworkSnapshot(t)
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return run(false, m, []string{"host-drift", "--baseline", path})
	})
	if code == 0 {
		t.Fatal("drift unexpectedly exited zero")
	}
	assertHostDriftEvidenceVisible(t, stdout, stderr, path)
	if !bytes.Equal(before, hostDriftNetworkSnapshot(t)) {
		t.Fatal("CLI drift mutated host network")
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("CLI drift created manager state")
	}
}

func TestHostDriftMenuShowsComponentEvidenceOnFailure(t *testing.T) {
	path := hostDriftRealChangedBaseline(t)
	m := sc.New(filepath.Join(t.TempDir(), "manager"), "", 0)
	in, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, err = writer.Write([]byte("15\n" + path + "\n0\n"))
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old; _ = in.Close() }()
	before := hostDriftNetworkSnapshot(t)
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return menu(m) })
	if code != 0 {
		t.Fatalf("menu exit code should mean normal menu exit: %d", code)
	}
	assertHostDriftEvidenceVisible(t, stdout, stderr, path)
	if !bytes.Equal(before, hostDriftNetworkSnapshot(t)) {
		t.Fatal("menu drift mutated host network")
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("menu drift created manager state")
	}
}

func TestHostDriftCLIRejectsIncompleteBaselineWithoutFakeData(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "manager"), "", 0)
	for _, tc := range []struct {
		name      string
		field     string
		jsonValue string
	}{
		{"links_empty", "links", "[]"},
		{"lookup_empty", "endpoint", `{"target":"127.0.0.1","family":"ipv4","kernel_route":[{}]}`},
		{"ipv4_rules_empty", "ipv4_rules", `[{}]`},
		{"ipv6_rules_missing_action", "ipv6_rules", `[{"priority":1}]`},
		{"missing_snapshot_atomic", "snapshot_atomic", "__DELETE__"},
		{"missing_activation_ready", "activation_ready", "__DELETE__"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := hostDriftRealChangedBaseline(t)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var doc map[string]json.RawMessage
			if err := json.Unmarshal(b, &doc); err != nil {
				t.Fatal(err)
			}
			var data map[string]json.RawMessage
			if err := json.Unmarshal(doc["data"], &data); err != nil {
				t.Fatal(err)
			}
			if tc.jsonValue == "__DELETE__" {
				delete(data, tc.field)
			} else {
				data[tc.field] = json.RawMessage(tc.jsonValue)
			}
			doc["data"], err = json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			b, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			code, stdout, _ := hostDriftCapturedOutput(t, func() int {
				return run(true, m, []string{"host-drift", "--baseline", path})
			})
			var result struct {
				OK    bool            `json:"ok"`
				Data  json.RawMessage `json:"data"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &result); err != nil {
				t.Fatal(err)
			}
			if code == 0 || result.OK || result.Error.Code != "invalid_baseline" || len(result.Data) != 0 || strings.Contains(stdout, path) {
				t.Fatalf("malformed baseline was not refused: code=%d body=%s", code, stdout)
			}
		})
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("invalid baseline created manager state")
	}
}
