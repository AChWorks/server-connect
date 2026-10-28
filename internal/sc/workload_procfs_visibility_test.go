package sc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func addUnobservableProcfsStat(t *testing.T, root string, pid string, malformed bool) {
	t.Helper()
	dir := filepath.Join(root, pid)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if malformed {
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(pid+" (bad) S garbage\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestWorkloadProcfsSkippedNumericEntriesVisibleInBothCensuses(t *testing.T) {
	root := workDescendantFixture(t)
	addUnobservableProcfsStat(t, root, "401", false) // transient, hidden or unreadable stat
	addUnobservableProcfsStat(t, root, "402", true)  // malformed unrelated stat
	if err := os.Mkdir(filepath.Join(root, "not-a-pid"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "403"), []byte("a numeric regular file"), 0600); err != nil {
		t.Fatal(err)
	}

	initial, skipped, err := workloadProcessCensusWithSkipsAt(root)
	if err != nil || skipped != 2 || initial[200].start != 200 ||
		len(initial) != 6 {
		t.Fatalf("initial skips or valid process map incorrect: skipped=%d census=%+v err=%v", skipped, initial, err)
	}

	report, err := observeWorkloadDescendantsAt(root, 200, false, func() {
		addUnobservableProcfsStat(t, root, "404", true) // only the second census sees this
	})
	if err != nil {
		t.Fatalf("valid selected tree with unrelated unreadable records failed: %v", err)
	}
	if report.ObservedDescendants == nil || len(*report.ObservedDescendants) != 3 ||
		report.Process.PID != 200 || !report.ReadOnly ||
		report.SnapshotAtomic || report.AttributionVerified ||
		report.DescendantsCovered || report.TrafficPathVerified ||
		report.ActivationReady {
		t.Fatalf("skipped unrelated records fabricated job/coverage authority: %+v", report)
	}
	var found bool
	for _, limitation := range report.Limitations {
		if strings.Contains(limitation, "Procfs numeric PID stat entries skipped") {
			found = true
			if !strings.Contains(limitation, "first census 2, second census 3") ||
				!strings.Contains(limitation, "including unrelated processes") ||
				!strings.Contains(limitation, "zero skips does not prove full descendant visibility") {
				t.Fatalf("misleading per-census visibility summary: %q", limitation)
			}
		}
	}
	if !found {
		t.Fatalf("skipped numeric entries omitted from conservative limitations: %+v", report.Limitations)
	}
}

func TestWorkloadProcfsZeroSkipsNeverMeansFullCoverage(t *testing.T) {
	root := workDescendantFixture(t)
	report, err := observeWorkloadDescendantsAt(root, 300, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if report.ObservedDescendants == nil || len(*report.ObservedDescendants) != 0 ||
		report.DescendantsCovered || report.AttributionVerified ||
		report.TrafficPathVerified || report.ActivationReady {
		t.Fatalf("zero-skipped zero-child sample was falsely complete: %+v", report)
	}
	if !strings.Contains(strings.Join(report.Limitations, "\n"), "first census 0, second census 0") ||
		!strings.Contains(strings.Join(report.Limitations, "\n"), "zero skips does not prove full descendant visibility") {
		t.Fatalf("missing zero-skip uncertainty warning: %+v", report.Limitations)
	}
}

func TestWorkloadProcfsSkippedSelectedRootOrChangedChildFailsClosed(t *testing.T) {
	root := workDescendantFixture(t)
	if err := os.Remove(filepath.Join(root, "200", "stat")); err != nil {
		t.Fatal(err)
	}
	report, err := observeWorkloadDescendantsAt(root, 200, false, nil)
	requireUnavailableWorkload(t, err)
	if report.Process.PID != 0 || report.ObservedDescendants != nil || len(report.Limitations) > 0 {
		t.Fatalf("unobservable selected root produced partial evidence: %+v", report)
	}

	root = workDescendantFixture(t)
	report, err = observeWorkloadDescendantsAt(root, 200, false, func() {
		if err := os.Remove(filepath.Join(root, "201", "stat")); err != nil {
			t.Fatal(err)
		}
	})
	requireUnavailableWorkload(t, err)
	if report.Process.PID != 0 || report.ObservedDescendants != nil || len(report.Limitations) > 0 {
		t.Fatalf("selected child disappearing during second census returned partial results: %+v", report)
	}
}

func TestWorkloadProcfsSkipCountsNeverBypassNumericLimit(t *testing.T) {
	root := t.TempDir()
	reader := &syntheticWorkloadProcDirReader{
		total: workloadDescendantMaxProcEntries + 1, numeric: true,
	}
	census, skipped, err := workloadProcessCensusFromReaderWithSkips(root, reader)
	requireUnavailableWorkload(t, err)
	if census != nil || skipped != 0 ||
		reader.position > workloadDescendantMaxProcEntries+workloadDescendantDirBatchSize {
		t.Fatalf("malformed numeric entries bypassed limit or leaked a partial count: skipped=%d result=%+v reader=%+v", skipped, census, reader)
	}
}
