package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPreflightRejectsAddressesBeforeAnyHostInspection(t *testing.T) {
	for _, tc := range []struct {
		endpoint string
		peer     string
	}{
		{"-o", ""},
		{"--help", ""},
		{"https://example.test/path", ""},
		{"example.com", ""},
		{"224.0.0.1", ""},
		{"0.0.0.0", ""},
		{"fe80::1%eth0", ""},
		{"::ffff:127.0.0.1", ""},
		{"", "not-an-ip"},
		{"", "ff02::1"},
	} {
		_, err := InspectHostRoutes(tc.endpoint, tc.peer)
		if err == nil || ErrorCode(err) != "invalid_arguments" {
			t.Fatalf("endpoint=%q peer=%q expected invalid_arguments, got %v", tc.endpoint, tc.peer, err)
		}
	}
}

func TestPreflightJSONValidationAndBounds(t *testing.T) {
	for _, value := range []string{`{"unexpected":"object"}`, "null", "[12]", `["string"]`, "{", ""} {
		if _, err := decodeRouteArray([]byte(value)); err == nil {
			t.Fatalf("accepted non-array or malformed route data: %q", value)
		}
	}
	if _, err := decodeRouteArray([]byte("[]")); err != nil {
		t.Fatalf("empty native route list is valid: %v", err)
	}
	if _, err := decodeRouteArray([]byte(`[{"dst":"default"}]`)); err != nil {
		t.Fatalf("valid route list rejected: %v", err)
	}
	var capture boundedIPOutput
	if _, err := capture.Write(bytes.Repeat([]byte("x"), hostSnapshotMaxBytes)); err != nil {
		t.Fatalf("capture exactly at limit rejected: %v", err)
	}
	if _, err := capture.Write([]byte("x")); err == nil {
		t.Fatal("capture over limit succeeded")
	}
	if capture.Len() != hostSnapshotMaxBytes {
		t.Fatal("over-limit write modified captured bytes")
	}
}

func TestPreflightCannotExecutePATHShadow(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux iproute2 test")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("native iproute2 not installed")
	}
	shadow := filepath.Join(t.TempDir(), "ip")
	if err := os.WriteFile(shadow, []byte("#!/bin/sh\nexit 91\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Dir(shadow))
	result, err := InspectHostRoutes("127.0.0.1", "")
	if err != nil || !result.ReadOnly || result.ActivationReady {
		t.Fatalf("host-preflight used untrusted PATH or made unsafe claim: %v", err)
	}
}

func TestPreflightNoHostMutationOrConnectivityAssertion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native Linux iproute2 test")
	}
	if _, err := os.Stat(nativeIPPath); err != nil {
		t.Skip("minimal CI container does not provide iproute2")
	}
	report, err := InspectHostRoutes("127.0.0.1", "127.0.0.2")
	if err != nil {
		t.Fatalf("real native iproute2 inspection: %v", err)
	}
	if !report.ReadOnly || report.ActivationReady || report.SnapshotAtomic || report.Mode != "observation_only" {
		t.Fatalf("unsafe readiness or snapshot claim: %+v", report)
	}
	for _, snapshot := range []json.RawMessage{report.Links, report.IPv4Routes, report.IPv6Routes, report.IPv4Rules, report.IPv6Rules} {
		if !json.Valid(snapshot) || !strings.HasPrefix(string(snapshot), "[") {
			t.Fatalf("invalid native JSON array: %s", snapshot)
		}
	}
	if report.Endpoint == nil || report.Endpoint.Target != "127.0.0.1" ||
		report.ManagementPeer == nil || report.ManagementPeer.Target != "127.0.0.2" {
		t.Fatalf("literal route lookup identity mismatch: %+v", report)
	}
	if len(report.Limitations) < 3 {
		t.Fatalf("missing explicit safety limitations")
	}
}
