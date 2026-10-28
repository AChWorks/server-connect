package sc

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func workDescendantFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeWorkloadFixture(t, root, 1, 0, 100, "/")
	writeWorkloadFixture(t, root, 200, 1, 200, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 201, 200, 301, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 202, 201, 302, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 203, 200, 303, "/system.slice/panel.service")
	writeWorkloadFixture(t, root, 300, 1, 400, "/system.slice/ssh.service")
	return root
}

func TestWorkloadDescendantsReadOnlyTreeExcludesUnrelatedPanelPeer(t *testing.T) {
	root := workDescendantFixture(t)
	report, err := observeWorkloadDescendantsAt(root, 200, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservedDescendants == nil || report.DescendantSurvey != "two_non_atomic_procfs_censuses" {
		t.Fatalf("missing explicit descendant evidence: %+v", report)
	}
	descendants := *report.ObservedDescendants
	if len(descendants) != 3 || descendants[0].Process.PID != 201 ||
		descendants[1].Process.PID != 202 || descendants[2].Process.PID != 203 {
		t.Fatalf("lost real parent-child scope or included unrelated sibling: %+v", descendants)
	}
	for _, child := range descendants {
		if child.Process.StartTimeTicks == 0 || child.Sockets != nil {
			t.Fatalf("fabricated socket evidence or lost birth ticks: %+v", child)
		}
	}
	if report.Mode != "observation_only" || !report.ReadOnly ||
		report.SnapshotAtomic || report.AttributionVerified || report.DescendantsCovered ||
		report.TrafficPathVerified || report.ActivationReady || len(report.Limitations) < 5 {
		t.Fatalf("tree was misrepresented as job selection or path proof: %+v", report)
	}
	// Even a stable process with zero children returns an explicit empty survey.
	empty, err := observeWorkloadDescendantsAt(root, 300, false, nil)
	if err != nil || empty.ObservedDescendants == nil || len(*empty.ObservedDescendants) != 0 {
		t.Fatalf("empty census was hidden or rejected: %+v %v", empty, err)
	}
}

func TestWorkloadDescendantsRejectsReusedAndReparentedChildren(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, root string)
	}{
		{"reused_grandchild", func(t *testing.T, root string) {
			writeWorkloadFixture(t, root, 202, 201, 999, "/system.slice/panel.service")
		}},
		{"reparented_child", func(t *testing.T, root string) {
			writeWorkloadFixture(t, root, 203, 1, 303, "/system.slice/panel.service")
		}},
		{"new_child", func(t *testing.T, root string) {
			writeWorkloadFixture(t, root, 204, 200, 304, "/system.slice/panel.service")
		}},
		{"disappeared_child", func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, "203")); err != nil {
				t.Fatal(err)
			}
		}},
		{"root_reuse", func(t *testing.T, root string) {
			writeWorkloadFixture(t, root, 200, 1, 900, "/system.slice/panel.service")
		}},
		{"cgroup_migration", func(t *testing.T, root string) {
			writeWorkloadFixture(t, root, 202, 201, 302, "/system.slice/other.service")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := workDescendantFixture(t)
			_, err := observeWorkloadDescendantsAt(root, 200, false, func() {
				tc.edit(t, root)
			})
			requireUnavailableWorkload(t, err)
		})
	}
}

func TestWorkloadDescendantsRejectsUnknownAndExcessiveScope(t *testing.T) {
	root := workDescendantFixture(t)
	if _, err := observeWorkloadDescendantsAt(root, 500, false, nil); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatalf("missing worker was accepted: %v", err)
	}
	if _, err := observeWorkloadDescendantsAt(root, 1, false, nil); ErrorCode(err) != "invalid_arguments" {
		t.Fatalf("init process was accepted: %v", err)
	}
	for i := 0; i <= workloadDescendantMaxChildren; i++ {
		writeWorkloadFixture(t, root, 1000+i, 200, uint64(1000+i), "/system.slice/panel.service")
	}
	if _, err := observeWorkloadDescendantsAt(root, 200, false, nil); ErrorCode(err) != "workload_observation_unavailable" {
		t.Fatalf("over-cap tree was partially accepted: %v", err)
	}
}

func TestWorkloadDescendantsRejectsMalformedAndOversizedSelectedNode(t *testing.T) {
	// Procfs census cannot trust a malformed selected row as a valid child.
	// The survey refuses a previously observed child that mutates afterward.
	for _, field := range []string{"stat", "cgroup"} {
		t.Run(field, func(t *testing.T) {
			root := workDescendantFixture(t)
			_, err := observeWorkloadDescendantsAt(root, 200, false, func() {
				if err := os.WriteFile(filepath.Join(root, "201", field), []byte(strings.Repeat("x", workloadProcMaxBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			})
			requireUnavailableWorkload(t, err)
		})
	}
}

func TestWorkloadDescendantsRealLinuxChildObservation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux procfs only")
	}
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil || !strings.HasPrefix(string(cgroups), "0::/") {
		t.Skip("requires unified Linux cgroup v2")
	}
	// No subprocesses or network configuration are created by the observer.
	// This process might have no children; it must still return a truthful survey.
	report, err := ObserveWorkloadProcessDescendants(os.Getpid(), false)
	if err != nil {
		t.Fatalf("real /proc snapshot unavailable: %v", err)
	}
	if report.ObservedDescendants == nil || report.Process.PID != os.Getpid() ||
		report.SnapshotAtomic || report.AttributionVerified || report.DescendantsCovered ||
		report.TrafficPathVerified || report.ActivationReady {
		t.Fatalf("real Linux snapshot claimed ownership: %+v", report)
	}
	for _, child := range *report.ObservedDescendants {
		if child.Process.PID <= 1 || child.Process.StartTimeTicks == 0 {
			t.Fatalf("invalid live process identity: %+v", child)
		}
	}
}
