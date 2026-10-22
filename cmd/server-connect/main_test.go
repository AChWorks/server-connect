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
