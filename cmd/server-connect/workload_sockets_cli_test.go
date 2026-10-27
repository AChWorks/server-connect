package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestWorkloadObserveCLISocketsAreExplicitAndNeverAuthorizeTraffic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs")
	}
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroups), "0::/") {
		t.Skip("unified cgroup v2 not exposed")
	}
	pid := strconv.Itoa(os.Getpid())
	code, plain := workloadRunJSON(t, "--pid", pid)
	if code != 0 || string(plain["ok"]) != "true" {
		t.Fatalf("plain snapshot failed: %d %v", code, plain)
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(plain["data"], &original); err != nil {
		t.Fatal(err)
	}
	if _, exposed := original["sockets"]; exposed {
		t.Fatalf("socket data exposed without explicit opt-in: %v", original)
	}

	code, optIn := workloadRunJSON(t, "--pid", pid, "--sockets")
	if code != 0 || string(optIn["ok"]) != "true" {
		t.Fatalf("opt-in observation failed: %d %v", code, optIn)
	}
	var data struct {
		ReadOnly            bool `json:"read_only"`
		AttributionVerified bool `json:"attribution_verified"`
		TrafficPathVerified bool `json:"traffic_path_verified"`
		ActivationReady     bool `json:"activation_ready"`
		Sockets             struct {
			ReadOnly            bool   `json:"read_only"`
			SnapshotAtomic      bool   `json:"snapshot_atomic"`
			JobOwnerVerified    bool   `json:"job_owner_verified"`
			TrafficPathVerified bool   `json:"traffic_path_verified"`
			DescendantsCovered  bool   `json:"descendants_covered"`
			ActivationReady     bool   `json:"activation_ready"`
			NetworkNamespace    string `json:"network_namespace"`
		} `json:"sockets"`
	}
	if err := json.Unmarshal(optIn["data"], &data); err != nil {
		t.Fatal(err)
	}
	if !data.ReadOnly || data.AttributionVerified || data.TrafficPathVerified ||
		data.ActivationReady || !data.Sockets.ReadOnly || data.Sockets.SnapshotAtomic ||
		data.Sockets.JobOwnerVerified || data.Sockets.TrafficPathVerified ||
		data.Sockets.DescendantsCovered || data.Sockets.ActivationReady ||
		!strings.HasPrefix(data.Sockets.NetworkNamespace, "net:[") {
		t.Fatalf("socket CLI claimed a job, path, or activation: %+v", data)
	}
}

func TestWorkloadObserveCLISocketsRefusesAbsentOrInvalidPID(t *testing.T) {
	for _, args := range [][]string{
		{"--sockets"}, {"--pid", "1", "--sockets"},
		{"--pid", "2147483647", "--sockets"},
		{"--pid", "2", "--sockets", "unrecognized"},
	} {
		code, body := workloadRunJSON(t, args...)
		if code == 0 || string(body["ok"]) != "false" || len(body["data"]) != 0 {
			t.Fatalf("unsafe socket CLI result args=%q: %v", args, body)
		}
	}
}
