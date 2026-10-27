package sc

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func workloadStatFixture(pid, parent int, start uint64, comm string) []byte {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[1] = strconv.Itoa(parent)
	fields[19] = strconv.FormatUint(start, 10)
	return []byte(fmt.Sprintf("%d (%s) %s\n", pid, comm, strings.Join(fields, " ")))
}

func writeWorkloadFixture(t *testing.T, root string, pid, parent int, start uint64, cgroup string) {
	t.Helper()
	dir := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), workloadStatFixture(pid, parent, start, "job ) with spaces"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte("0::"+cgroup+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadObserveStatAndCgroupParsing(t *testing.T) {
	parent, start, err := parseWorkloadStat(workloadStatFixture(4321, 47, 894200, "odd ) value ( and spaces"), 4321)
	if err != nil || parent != 47 || start != 894200 {
		t.Fatalf("comm/stat parsing lost process generation: %d %d %v", parent, start, err)
	}
	for _, data := range [][]byte{
		workloadStatFixture(4322, 47, 894200, "normal"),
		[]byte("4321 (broken) S 5 0"),
		workloadStatFixture(4321, 4321, 894200, "self parent"),
		workloadStatFixture(4321, 47, 0, "no birth"),
		[]byte("4321 (improper) Z 5 0"),
	} {
		if _, _, err := parseWorkloadStat(data, 4321); ErrorCode(err) != "workload_observation_unavailable" {
			t.Errorf("invalid stat accepted: %q", data)
		}
	}
	if path, err := parseWorkloadCgroup([]byte("0::/system.slice/example.service\n")); err != nil || path != "/system.slice/example.service" {
		t.Fatalf("v2 cgroup rejected: %q %v", path, err)
	}
	for _, input := range []string{"4:cpu:/system.slice/test\n", "0::/foo\n1:name=systemd:/bar\n", "0::foo\n", "0::/a/../b\n", "0::/test\r\n", "0::/foo\x00bar\n", ""} {
		if _, err := parseWorkloadCgroup([]byte(input)); ErrorCode(err) != "workload_observation_unavailable" {
			t.Errorf("accepted ambiguous cgroup: %q", input)
		}
	}
}

func TestWorkloadObserveFixtureAncestryAndFailClosedReuse(t *testing.T) {
	root := t.TempDir()
	writeWorkloadFixture(t, root, 1, 0, 100, "/")
	writeWorkloadFixture(t, root, 200, 1, 200, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 201, 200, 300, "/system.slice/panel.service")
	report, err := observeWorkloadAt(root, 201)
	if err != nil {
		t.Fatal(err)
	}
	if report.Mode != "observation_only" || !report.ReadOnly || report.SnapshotAtomic || report.AttributionVerified || report.ActivationReady || report.TrafficPathVerified || report.DescendantsCovered || !report.SharesParentCgroup || len(report.Limitations) == 0 {
		t.Fatalf("unsafe result or missing conservative scope: %+v", report)
	}
	if report.Process.PID != 201 || report.Process.StartTimeTicks != 300 || len(report.Ancestors) != 2 || report.Ancestors[0].PID != 200 || report.Ancestors[1].PID != 1 {
		t.Fatalf("wrong parent/ancestor provenance: %+v", report)
	}
	if err := recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)); err != nil {
		t.Fatal(err)
	}
	// A process generation change and a migrated cgroup must invalidate a
	// prior receipt; an observed PID/path string is never an ownership token.
	writeWorkloadFixture(t, root, 201, 200, 301, "/system.slice/panel.service")
	if err := recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatal("PID reuse was not detected", err)
	}
	writeWorkloadFixture(t, root, 201, 200, 300, "/system.slice/other.service")
	if err := recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatal("cgroup migration was not detected", err)
	}
	writeWorkloadFixture(t, root, 201, 200, 300, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 200, 1, 202, "/system.slice/panel.service")
	if err := recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatal("reused parent PID was not detected", err)
	}
	if _, err := observeWorkloadAt(root, 202); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatal("nonexistent worker accepted", err)
	}
	if _, err := observeWorkloadAt(root, 0); ErrorCode(err) != "invalid_arguments" {
		t.Fatal("zero PID accepted", err)
	}
	if _, err := observeWorkloadAt(root, 1); ErrorCode(err) != "invalid_arguments" {
		t.Fatal("init PID accepted", err)
	}
}

func TestWorkloadObserveLiveOwnProcessOrUnsupportedHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs diagnostic")
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(data), "0::/") {
		t.Skip("unified cgroup v2 procfs not available")
	}
	report, err := ObserveWorkloadProcess(os.Getpid())
	if err != nil {
		t.Fatalf("current live PID must be observable when procfs supports cgroup v2: %v", err)
	}
	if report.Process.PID != os.Getpid() || report.Process.StartTimeTicks == 0 || !report.ReadOnly || report.ActivationReady || report.AttributionVerified || report.TrafficPathVerified {
		t.Fatalf("live PID produced false job or traffic evidence: %+v", report)
	}
}

// These are actual fail-closed observation regressions, not merely checks that
// the source contains a guard. No live kernel process, cgroup or routing state
// is created or modified: every case uses a private synthetic procfs tree.
func requireUnavailableWorkload(t *testing.T, err error) {
	t.Helper()
	if ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatalf("expected classified unavailable (no fabricated worker), got %v", err)
	}
}

func TestWorkloadObserveRejectsObservedReparentingWithSameGeneration(t *testing.T) {
	root := t.TempDir()
	writeWorkloadFixture(t, root, 1, 0, 10, "/")
	writeWorkloadFixture(t, root, 200, 1, 20, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 201, 200, 30, "/system.slice/panel.service")
	observed, err := observeWorkloadAt(root, 201)
	if err != nil || len(observed.Ancestors) != 2 {
		t.Fatalf("expected fixture baseline: %+v, %v", observed, err)
	}
	original := append([]WorkloadProcessIdentity{observed.Process}, observed.Ancestors...)

	// A child may be reparented while retaining the same PID and birth ticks.
	// The ancestry recheck must compare parent PID, not just process generation.
	writeWorkloadFixture(t, root, 201, 1, 30, "/system.slice/panel.service")
	requireUnavailableWorkload(t, recheckWorkloadAncestryAt(root, original))
}

func TestWorkloadObserveRejectsMissingParentAndCyclicAncestry(t *testing.T) {
	t.Run("missing_parent", func(t *testing.T) {
		root := t.TempDir()
		writeWorkloadFixture(t, root, 201, 200, 30, "/system.slice/panel.service")
		_, err := observeWorkloadAt(root, 201)
		requireUnavailableWorkload(t, err)
	})
	t.Run("parent_disappeared_after_snapshot", func(t *testing.T) {
		root := t.TempDir()
		writeWorkloadFixture(t, root, 1, 0, 10, "/")
		writeWorkloadFixture(t, root, 200, 1, 20, "/system.slice/panel.service")
		writeWorkloadFixture(t, root, 201, 200, 30, "/system.slice/panel.service")
		report, err := observeWorkloadAt(root, 201)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(root, "200", "stat")); err != nil {
			t.Fatal(err)
		}
		requireUnavailableWorkload(t, recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)))
	})
	t.Run("cycle", func(t *testing.T) {
		root := t.TempDir()
		writeWorkloadFixture(t, root, 201, 200, 30, "/system.slice/panel.service")
		writeWorkloadFixture(t, root, 200, 201, 20, "/system.slice/panel.service")
		_, err := observeWorkloadAt(root, 201)
		requireUnavailableWorkload(t, err)
	})
	t.Run("self_parent", func(t *testing.T) {
		root := t.TempDir()
		writeWorkloadFixture(t, root, 201, 201, 30, "/system.slice/panel.service")
		_, err := observeWorkloadAt(root, 201)
		requireUnavailableWorkload(t, err)
	})
}

func TestWorkloadObserveAncestryDepthBoundary(t *testing.T) {
	root := t.TempDir()
	const firstPID = 1000
	// Exactly the maximum bounded chain length is acceptable. A process
	// beyond the visible root may have parent 0 without granting proof of
	// complete ancestry or source-job ownership.
	for i := 0; i < workloadAncestryMaxDepth; i++ {
		parent := firstPID + i + 1
		if i == workloadAncestryMaxDepth-1 {
			parent = 0
		}
		writeWorkloadFixture(t, root, firstPID+i, parent, uint64(100+i), "/system.slice/panel.service")
	}
	report, err := observeWorkloadAt(root, firstPID)
	if err != nil || len(report.Ancestors) != workloadAncestryMaxDepth-1 || report.AttributionVerified || report.DescendantsCovered || report.ActivationReady {
		t.Fatalf("failed exact-capacity namespace-boundary observation: %+v, %v", report, err)
	}

	// The same chain now contains one extra process: this must fail closed
	// rather than truncate the ancestry and claim that observation succeeded.
	writeWorkloadFixture(t, root, firstPID+workloadAncestryMaxDepth-1, firstPID+workloadAncestryMaxDepth, 100+workloadAncestryMaxDepth-1, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, firstPID+workloadAncestryMaxDepth, 0, 100+workloadAncestryMaxDepth, "/system.slice/panel.service")
	_, err = observeWorkloadAt(root, firstPID)
	requireUnavailableWorkload(t, err)
}

func TestWorkloadObserveRejectsOversizedProcfsRecords(t *testing.T) {
	for _, field := range []string{"stat", "cgroup"} {
		t.Run(field, func(t *testing.T) {
			root := t.TempDir()
			writeWorkloadFixture(t, root, 201, 0, 30, "/system.slice/panel.service")
			path := filepath.Join(root, "201", field)
			if err := os.WriteFile(path, []byte(strings.Repeat("x", workloadProcMaxBytes+1)), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := observeWorkloadAt(root, 201)
			requireUnavailableWorkload(t, err)
		})
	}
}

func TestWorkloadObserveNamespaceHiddenParentNeverClaimsJobIdentity(t *testing.T) {
	root := t.TempDir()
	writeWorkloadFixture(t, root, 201, 0, 30, "/system.slice/panel.service")
	report, err := observeWorkloadAt(root, 201)
	if err != nil || len(report.Ancestors) != 0 {
		t.Fatalf("unrepresented namespace parent was misclassified: %+v, %v", report, err)
	}
	if !report.ReadOnly || report.SnapshotAtomic || report.AttributionVerified || report.DescendantsCovered || report.TrafficPathVerified || report.ActivationReady || report.SharesParentCgroup {
		t.Fatalf("missing parent gave false workload ownership or path proof: %+v", report)
	}
}
