package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestWorkloadObserveCLIDescendantsAreOptInAndNeverClaimJobOwnership(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroups), "0::/") {
		t.Skip("requires unified cgroup v2 procfs")
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no disposable sleep fixture available")
	}
	cmd := exec.Command(sleep, "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	rootPID := strconv.Itoa(os.Getpid())
	code, plain := workloadRunJSON(t, "--pid", rootPID)
	if code != 0 || string(plain["ok"]) != "true" {
		t.Fatalf("ordinary read-only observation failed: %d %v", code, plain)
	}
	var defaultData map[string]json.RawMessage
	if err := json.Unmarshal(plain["data"], &defaultData); err != nil {
		t.Fatal(err)
	}
	if _, found := defaultData["observed_descendants"]; found {
		t.Fatal("descendant data exposed without opt in")
	}
	if _, found := defaultData["descendant_survey"]; found {
		t.Fatal("descendant survey exposed without opt in")
	}

	code, withoutSockets := workloadRunJSON(t, "--pid", rootPID, "--descendants")
	if code != 0 || string(withoutSockets["ok"]) != "true" {
		t.Fatalf("child-only observation failed: %d %v", code, withoutSockets)
	}
	var childOnly map[string]json.RawMessage
	if err := json.Unmarshal(withoutSockets["data"], &childOnly); err != nil {
		t.Fatal(err)
	}
	if _, found := childOnly["sockets"]; found {
		t.Fatal("parent socket observations leaked without --sockets")
	}
	var childrenOnly []map[string]json.RawMessage
	if err := json.Unmarshal(childOnly["observed_descendants"], &childrenOnly); err != nil {
		t.Fatal(err)
	}
	foundChild := false
	for _, child := range childrenOnly {
		if _, found := child["sockets"]; found {
			t.Fatal("child socket observations leaked without --sockets")
		}
		var process struct {
			PID int `json:"pid"`
		}
		if err := json.Unmarshal(child["process"], &process); err != nil {
			t.Fatal(err)
		}
		if process.PID == cmd.Process.Pid {
			foundChild = true
		}
	}
	if !foundChild {
		t.Fatalf("real child omitted from child-only result: %v", childrenOnly)
	}

	code, observed := workloadRunJSON(t, "--pid", rootPID, "--descendants", "--sockets")
	if code != 0 || string(observed["ok"]) != "true" || len(observed["error"]) != 0 {
		t.Fatalf("opt-in child observation failed: %d %v", code, observed)
	}
	var data struct {
		ReadOnly            bool   `json:"read_only"`
		DescendantSurvey    string `json:"descendant_survey"`
		SnapshotAtomic      bool   `json:"snapshot_atomic"`
		AttributionVerified bool   `json:"attribution_verified"`
		DescendantsCovered  bool   `json:"descendants_covered"`
		TrafficPathVerified bool   `json:"traffic_path_verified"`
		ActivationReady     bool   `json:"activation_ready"`
		Children            []struct {
			Process struct {
				PID            int    `json:"pid"`
				ParentPID      int    `json:"parent_pid"`
				StartTimeTicks uint64 `json:"start_time_ticks"`
			} `json:"process"`
			Sockets *struct {
				ReadOnly            bool `json:"read_only"`
				JobOwnerVerified    bool `json:"job_owner_verified"`
				TrafficPathVerified bool `json:"traffic_path_verified"`
				DescendantsCovered  bool `json:"descendants_covered"`
				ActivationReady     bool `json:"activation_ready"`
			} `json:"sockets"`
		} `json:"observed_descendants"`
	}
	if err := json.Unmarshal(observed["data"], &data); err != nil {
		t.Fatal(err)
	}
	if !data.ReadOnly || data.DescendantSurvey != "two_non_atomic_procfs_censuses" ||
		data.SnapshotAtomic || data.AttributionVerified || data.DescendantsCovered ||
		data.TrafficPathVerified || data.ActivationReady {
		t.Fatalf("child observation falsely authorized routing: %+v", data)
	}
	foundSleep := false
	for _, child := range data.Children {
		if child.Process.PID == cmd.Process.Pid {
			if child.Process.ParentPID != os.Getpid() || child.Process.StartTimeTicks == 0 ||
				child.Sockets == nil || !child.Sockets.ReadOnly || child.Sockets.JobOwnerVerified ||
				child.Sockets.TrafficPathVerified || child.Sockets.DescendantsCovered || child.Sockets.ActivationReady {
				t.Fatalf("real Linux child has unsafe or incorrect evidence: %+v", child)
			}
			foundSleep = true
		}
	}
	if !foundSleep {
		t.Fatalf("real child %d was omitted: %+v", cmd.Process.Pid, data.Children)
	}
}

func TestWorkloadObserveCLIDescendantsRejectInvalidAndMissingPID(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code string
	}{
		{[]string{"--descendants", "--pid", "1"}, "invalid_arguments"},
		{[]string{"--descendants", "--pid", "2147483647"}, "workload_observation_unavailable"},
		{[]string{"--descendants", "--pid", "2", "stray"}, "invalid_arguments"},
	} {
		exit, data := workloadRunJSON(t, tc.args...)
		if exit == 0 || string(data["ok"]) != "false" || !strings.Contains(string(data["error"]), tc.code) || len(data["data"]) > 0 {
			t.Fatalf("invalid descendant CLI produced partial success: %+v exit=%d", data, exit)
		}
	}
}
