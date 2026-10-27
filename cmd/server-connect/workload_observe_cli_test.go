package main

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func workloadRunJSON(t *testing.T, args ...string) (int, map[string]json.RawMessage) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old; _ = r.Close() }()
	code := run(true, nil, append([]string{"workload-observe"}, args...))
	_ = w.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("bad JSON envelope %v: %s", err, raw)
	}
	return code, data
}

func TestWorkloadObserveCLIRejectsUntrustedOrMissingPID(t *testing.T) {
	for _, args := range [][]string{
		{}, {"--pid", "0"}, {"--pid", "1"}, {"--pid", "-1"}, {"--pid", "not-a-pid"},
		{"--pid", "2", "extra"}, {"--pid", "2", "--not-an-option"},
	} {
		code, body := workloadRunJSON(t, args...)
		if code == 0 || string(body["ok"]) != "false" || !strings.Contains(string(body["error"]), "invalid_arguments") || len(body["data"]) != 0 {
			t.Fatalf("invalid command selected workload: args=%q code=%d payload=%v", args, code, body)
		}
	}
}

func TestWorkloadObserveCLIMissingProcessDoesNotInventData(t *testing.T) {
	code, body := workloadRunJSON(t, "--pid", "2147483647")
	if code == 0 || string(body["ok"]) != "false" || len(body["data"]) != 0 || !strings.Contains(string(body["error"]), "workload_observation_unavailable") {
		t.Fatalf("missing process manufactured an observation: code=%d payload=%v", code, body)
	}
}

func TestWorkloadObserveCLIHonestLiveSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs")
	}
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroups), "0::/") {
		t.Skip("unified cgroup v2 not exposed")
	}
	code, body := workloadRunJSON(t, "--pid", strconv.Itoa(os.Getpid()))
	if code != 0 || string(body["ok"]) != "true" || len(body["error"]) != 0 {
		t.Fatalf("live process observation error: code=%d %v", code, body)
	}
	var data struct {
		ReadOnly            bool `json:"read_only"`
		SnapshotAtomic      bool `json:"snapshot_atomic"`
		ActivationReady     bool `json:"activation_ready"`
		AttributionVerified bool `json:"attribution_verified"`
		DescendantsCovered  bool `json:"descendants_covered"`
		TrafficPathVerified bool `json:"traffic_path_verified"`
		Process             struct {
			PID        int    `json:"pid"`
			StartTicks uint64 `json:"start_time_ticks"`
		} `json:"process"`
	}
	if err := json.Unmarshal(body["data"], &data); err != nil {
		t.Fatal(err)
	}
	if !data.ReadOnly || data.SnapshotAtomic || data.ActivationReady || data.AttributionVerified || data.DescendantsCovered || data.TrafficPathVerified || data.Process.PID != os.Getpid() || data.Process.StartTicks == 0 {
		t.Fatalf("false workload egress or ownership claim: %+v", data)
	}
}
