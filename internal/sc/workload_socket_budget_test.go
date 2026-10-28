package sc

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func socketBudgetDescendantFixture(t *testing.T) string {
	t.Helper()
	root := workDescendantFixture(t)
	for _, pid := range []int{200, 201, 202, 203} {
		dir := filepath.Join(root, strconv.Itoa(pid))
		for _, sub := range []string{"fd", "net", "ns"} {
			if err := os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink("net:[4026531993]", filepath.Join(dir, "ns", "net")); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
			if err := os.WriteFile(filepath.Join(dir, "net", table), []byte(workloadSocketTestHeader), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// This socket exists only in the first child; all other per-PID tables
	// remain valid but empty to make the byte budget deterministic.
	if err := os.Symlink("socket:[12345]", filepath.Join(root, "201", "fd", "3")); err != nil {
		t.Fatal(err)
	}
	row := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
	if err := os.WriteFile(filepath.Join(root, "201", "net", "tcp"),
		[]byte(workloadSocketTestHeader+row), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func socketBudgetFixtureTableBytes() int64 {
	// Root and three children: four tables per PID, plus one valid row on
	// the first child's tcp table.
	row := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
	return int64(4*4*len(workloadSocketTestHeader) + len(row))
}

func TestWorkloadSocketAggregateBudgetAtExactBoundary(t *testing.T) {
	root := socketBudgetDescendantFixture(t)
	budget := &workloadSocketReadBudget{remaining: socketBudgetFixtureTableBytes()}
	report, err := observeWorkloadDescendantsAtWithBudget(root, 200, true, nil, budget)
	if err != nil {
		t.Fatalf("exact aggregate byte limit was rejected: %v", err)
	}
	if budget.remaining != 0 {
		t.Fatalf("aggregate socket input accounting lost bytes: %d", budget.remaining)
	}
	if report.ObservedDescendants == nil || len(*report.ObservedDescendants) != 3 ||
		report.Sockets == nil || report.AttributionVerified ||
		report.TrafficPathVerified || report.DescendantsCovered || report.ActivationReady {
		t.Fatalf("observation falsely authorized job traffic: %+v", report)
	}
	first := (*report.ObservedDescendants)[0]
	if first.Process.PID != 201 || first.Sockets == nil ||
		len(first.Sockets.ObservedTCPUDPSocket) != 1 ||
		first.Sockets.ObservedTCPUDPSocket[0].Inode != 12345 ||
		first.Sockets.JobOwnerVerified || first.Sockets.TrafficPathVerified {
		t.Fatalf("budget accounting changed socket FD join: %+v", first)
	}
}

func TestWorkloadSocketAggregateBudgetExhaustedAfterObservedChildDiscardsAllEvidence(t *testing.T) {
	root := socketBudgetDescendantFixture(t)
	// Root + first child succeed; the second child consumes two tables before
	// the budget reaches zero. Later failure must discard root AND child data.
	perPID := int64(4 * len(workloadSocketTestHeader))
	firstChild := perPID + int64(len(socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")))
	budget := &workloadSocketReadBudget{remaining: perPID + firstChild + 2*int64(len(workloadSocketTestHeader))}
	report, err := observeWorkloadDescendantsAtWithBudget(root, 200, true, nil, budget)
	requireUnavailableWorkload(t, err)
	if report.Process.PID != 0 || report.Sockets != nil || report.ObservedDescendants != nil ||
		report.Mode != "" || budget.remaining != 0 {
		t.Fatalf("exhausted aggregate budget leaked evidence or miscounted input: report=%+v budget=%+v", report, budget)
	}
}

func TestWorkloadSocketAggregateBudgetRejectsLargeParseableTableBeforeCompleteRead(t *testing.T) {
	root := newWorkloadSocketFixture(t)
	addWorkloadSocketFD(t, root, 3, 12345)
	row := socketRow(12345, "0100007F:EA60", "0200007F:0050", "01")
	// This is a complete native-shaped table, not malformed padding. The
	// observer must refuse because of budget, not because the parser failed.
	large := workloadSocketTestHeader + strings.Repeat(row, 200)
	path := filepath.Join(root, "201", "net", "tcp")
	if err := os.WriteFile(path, []byte(large), 0600); err != nil {
		t.Fatal(err)
	}
	if sockets, err := readWorkloadSocketTable(root, 201, "tcp4", map[uint64]bool{12345: true}); err != nil || len(sockets) != 200 {
		t.Fatalf("control: valid large table should parse without an aggregate budget: %d %v", len(sockets), err)
	}
	limited := &workloadSocketReadBudget{remaining: int64(len(large) - 1)}
	if sockets, err := readWorkloadSocketTableWithBudget(root, 201, "tcp4", map[uint64]bool{12345: true}, limited); ErrorCode(err) != "workload_observation_unavailable" || len(sockets) != 0 {
		t.Fatalf("over-budget parseable table accepted: %d %v", len(sockets), err)
	}
	if limited.remaining != int64(len(large)-1) {
		t.Fatalf("a failed table read must not decrement the success-only consumed budget: %+v", limited)
	}
	exact := &workloadSocketReadBudget{remaining: int64(len(large))}
	sockets, err := readWorkloadSocketTableWithBudget(root, 201, "tcp4", map[uint64]bool{12345: true}, exact)
	if err != nil || len(sockets) != 200 || exact.remaining != 0 {
		t.Fatalf("exact table boundary rejected or miscounted: %d %v budget=%+v", len(sockets), err, exact)
	}
}

func TestWorkloadSocketAggregateBudgetRejectsZeroAndMissingContext(t *testing.T) {
	root := socketBudgetDescendantFixture(t)
	for _, budget := range []*workloadSocketReadBudget{nil, {remaining: 0}, {remaining: -1}} {
		report, err := observeWorkloadDescendantsAtWithBudget(root, 200, true, nil, budget)
		requireUnavailableWorkload(t, err)
		if report.Process.PID != 0 || report.Sockets != nil || report.ObservedDescendants != nil {
			t.Fatalf("missing or invalid budget emitted data: %+v", report)
		}
	}
	// Child-only sampling remains free of socket scans and their budget.
	report, err := observeWorkloadDescendantsAtWithBudget(root, 200, false, nil, nil)
	if err != nil || report.Sockets != nil || report.ObservedDescendants == nil ||
		len(*report.ObservedDescendants) != 3 {
		t.Fatalf("read-only child sampling incorrectly depends on socket budget: %+v %v", report, err)
	}
}

func TestWorkloadSocketAggregateBudgetProductionLimitAndSafetyFlags(t *testing.T) {
	if workloadSocketDescendantMaxNetBytes != 64<<20 {
		t.Fatal("production cumulative socket table byte limit was silently changed")
	}
	root := socketBudgetDescendantFixture(t)
	report, err := observeWorkloadDescendantsAt(root, 200, true, nil)
	if err != nil || report.Sockets == nil || report.ObservedDescendants == nil ||
		report.SnapshotAtomic || report.AttributionVerified || report.DescendantsCovered ||
		report.TrafficPathVerified || report.ActivationReady {
		t.Fatalf("production budget path wrongly rejected or claimed authority: %+v %v", report, err)
	}
}
