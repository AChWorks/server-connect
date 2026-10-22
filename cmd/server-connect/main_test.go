package main

import (
	"encoding/json"
	"os"
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
