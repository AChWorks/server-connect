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
