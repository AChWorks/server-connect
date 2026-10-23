package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
