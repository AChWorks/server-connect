package sc

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
)

// WorkloadDescendantObservation is a time-limited observation of an actually
// visible child process. It is never an ownership claim for a panel task.
type WorkloadDescendantObservation struct {
	Process WorkloadProcessIdentity `json:"process"`
	Sockets *WorkloadSocketEvidence `json:"sockets,omitempty"`
}

type workloadProcCensusEntry struct {
	parent int
	start  uint64
}

const (
	workloadDescendantMaxProcEntries = 8192
	// Include nonnumeric entries in the limit: procfs has global files and
	// directories as well as per-PID directories.
	workloadDescendantMaxDirEntries = workloadDescendantMaxProcEntries + 256
	workloadDescendantDirBatchSize  = 128
	workloadDescendantMaxChildren   = 64
)

// The private reader seam lets tests verify bounded streaming without
// provisioning thousands of real host processes. Production always uses an
// opened /proc directory; n must stay strictly positive and finite.
type workloadProcDirReader interface {
	ReadDir(n int) ([]os.DirEntry, error)
}

// A procfs census does not claim to observe all processes or threads.
// Transient or inaccessible unrelated entries are skipped; every selected
// candidate is rechecked separately and the two selected trees must agree.
func workloadProcessCensusAt(root string) (map[int]workloadProcCensusEntry, error) {
	census, _, err := workloadProcessCensusWithSkipsAt(root)
	return census, err
}

// Counts are only directly observed skipped numeric stat entries, not hidden
// processes, authenticated job coverage, or an estimate of missed children.
func workloadProcessCensusWithSkipsAt(root string) (map[int]workloadProcCensusEntry, int, error) {
	dir, err := os.Open(root)
	if err != nil {
		return nil, 0, workloadObservationUnavailable()
	}
	defer dir.Close()
	return workloadProcessCensusFromReaderWithSkips(root, dir)
}

func workloadProcessCensusFromReader(root string, dir workloadProcDirReader) (map[int]workloadProcCensusEntry, error) {
	census, _, err := workloadProcessCensusFromReaderWithSkips(root, dir)
	return census, err
}

func workloadProcessCensusFromReaderWithSkips(root string, dir workloadProcDirReader) (map[int]workloadProcCensusEntry, int, error) {
	observed := make(map[int]workloadProcCensusEntry)
	total, numeric, skipped := 0, 0, 0
	for {
		// Request at most one entry beyond the total cap, so even the
		// exhaustion check cannot materialize an unbounded directory slice.
		batchSize := workloadDescendantDirBatchSize
		if remaining := workloadDescendantMaxDirEntries - total + 1; remaining < batchSize {
			batchSize = remaining
		}
		entries, err := dir.ReadDir(batchSize)
		if (err != nil && err != io.EOF) || len(entries) > batchSize {
			return nil, 0, workloadObservationUnavailable()
		}
		total += len(entries)
		if total > workloadDescendantMaxDirEntries {
			return nil, 0, workloadObservationUnavailable()
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil || pid < 1 {
				continue
			}
			numeric++
			if numeric > workloadDescendantMaxProcEntries {
				return nil, 0, workloadObservationUnavailable()
			}
			stat, err := readWorkloadProcFile(filepath.Join(root, entry.Name(), "stat"))
			if err != nil {
				skipped++
				continue
			}
			parent, start, err := parseWorkloadStat(stat, pid)
			if err != nil {
				skipped++
				continue
			}
			observed[pid] = workloadProcCensusEntry{parent: parent, start: start}
		}
		if err == io.EOF {
			return observed, skipped, nil
		}
		// A positive-size ReadDir must never return an empty, successful batch.
		if len(entries) == 0 {
			return nil, 0, workloadObservationUnavailable()
		}
	}
}

func workloadDescendantsFromCensus(census map[int]workloadProcCensusEntry, rootPID int) ([]int, error) {
	if _, ok := census[rootPID]; !ok {
		return nil, workloadObservationUnavailable()
	}
	byParent := make(map[int][]int)
	for pid, entry := range census {
		if pid != rootPID {
			byParent[entry.parent] = append(byParent[entry.parent], pid)
		}
	}
	for parent := range byParent {
		sort.Ints(byParent[parent])
	}
	visited := map[int]bool{rootPID: true}
	pending := []int{rootPID}
	result := make([]int, 0)
	for len(pending) > 0 {
		parent := pending[0]
		pending = pending[1:]
		for _, child := range byParent[parent] {
			if visited[child] {
				return nil, workloadObservationUnavailable()
			}
			visited[child] = true
			result = append(result, child)
			if len(result) > workloadDescendantMaxChildren {
				return nil, workloadObservationUnavailable()
			}
			pending = append(pending, child)
		}
	}
	sort.Ints(result)
	return result, nil
}

func sameWorkloadDescendantTree(first, last map[int]workloadProcCensusEntry, firstPIDs, lastPIDs []int, rootPID int) bool {
	if len(firstPIDs) != len(lastPIDs) || first[rootPID] != last[rootPID] {
		return false
	}
	for i := range firstPIDs {
		if firstPIDs[i] != lastPIDs[i] || first[firstPIDs[i]] != last[lastPIDs[i]] {
			return false
		}
	}
	return true
}

func workloadTreeContainsRoot(report WorkloadObservation, rootPID int, rootStart uint64) bool {
	for _, ancestor := range report.Ancestors {
		if ancestor.PID == rootPID && ancestor.StartTimeTicks == rootStart {
			return true
		}
	}
	return false
}

func observeWorkloadDescendantsAt(root string, pid int, sockets bool, afterEvidence func()) (WorkloadObservation, error) {
	var budget *workloadSocketReadBudget
	if sockets {
		budget = &workloadSocketReadBudget{remaining: workloadSocketDescendantMaxNetBytes}
	}
	return observeWorkloadDescendantsAtWithBudget(root, pid, sockets, afterEvidence, budget)
}

// The budget seam remains package-private for precise synthetic fixtures;
// production uses the fixed cumulative limit only when --sockets is opted in.
func observeWorkloadDescendantsAtWithBudget(root string, pid int, sockets bool, afterEvidence func(), budget *workloadSocketReadBudget) (WorkloadObservation, error) {
	if pid <= 1 {
		return WorkloadObservation{}, Fault("invalid_arguments", "workload observation requires --pid greater than 1")
	}
	if sockets && (budget == nil || budget.remaining <= 0) {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	before, beforeSkipped, err := workloadProcessCensusWithSkipsAt(root)
	if err != nil {
		return WorkloadObservation{}, err
	}
	children, err := workloadDescendantsFromCensus(before, pid)
	if err != nil {
		return WorkloadObservation{}, err
	}
	var report WorkloadObservation
	if sockets {
		report, err = observeWorkloadWithSocketsAtBudget(root, pid, budget)
	} else {
		report, err = observeWorkloadAt(root, pid)
	}
	if err != nil {
		return WorkloadObservation{}, err
	}
	if before[pid].start != report.Process.StartTimeTicks || before[pid].parent != report.Process.ParentPID {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	evidence := make([]WorkloadDescendantObservation, 0, len(children))
	chains := make([][]WorkloadProcessIdentity, 0, len(children))
	for _, child := range children {
		var observed WorkloadObservation
		if sockets {
			observed, err = observeWorkloadWithSocketsAtBudget(root, child, budget)
		} else {
			observed, err = observeWorkloadAt(root, child)
		}
		if err != nil {
			return WorkloadObservation{}, err
		}
		original := before[child]
		if observed.Process.ParentPID != original.parent ||
			observed.Process.StartTimeTicks != original.start ||
			!workloadTreeContainsRoot(observed, pid, report.Process.StartTimeTicks) {
			return WorkloadObservation{}, workloadObservationUnavailable()
		}
		evidence = append(evidence, WorkloadDescendantObservation{
			Process: observed.Process, Sockets: observed.Sockets,
		})
		chains = append(chains, append([]WorkloadProcessIdentity{observed.Process}, observed.Ancestors...))
	}
	if afterEvidence != nil {
		afterEvidence()
	}
	after, afterSkipped, err := workloadProcessCensusWithSkipsAt(root)
	if err != nil {
		return WorkloadObservation{}, err
	}
	lastChildren, err := workloadDescendantsFromCensus(after, pid)
	if err != nil || !sameWorkloadDescendantTree(before, after, children, lastChildren, pid) {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	if err = recheckWorkloadAncestryAt(root, append([]WorkloadProcessIdentity{report.Process}, report.Ancestors...)); err != nil {
		return WorkloadObservation{}, err
	}
	for _, chain := range chains {
		if err := recheckWorkloadAncestryAt(root, chain); err != nil {
			return WorkloadObservation{}, err
		}
	}
	report.ObservedDescendants = &evidence
	report.DescendantSurvey = "two_non_atomic_procfs_censuses"
	report.Limitations = append(report.Limitations,
		fmt.Sprintf("Procfs numeric PID stat entries skipped: first census %d, second census %d. These are observed unreadable, missing or malformed stat entries, including unrelated processes; zero skips does not prove full descendant visibility.", beforeSkipped, afterSkipped),
		"Observed descendants are only a bounded two-census procfs sample; short-lived, hidden and newly forked processes can be missed, and PID namespace boundaries can hide workers.",
		"Shared cgroup/process ancestry, inherited sockets and observed child FDs do not authenticate aaPanel task IDs or exclusive job traffic.",
		"No continuous child capture, DNS/packet-path verification, VPN egress selection, routing authorization or active guard is provided.",
	)
	return report, nil
}

// ObserveWorkloadProcessDescendants gathers an opt-in read-only snapshot of
// currently visible children and optional socket FDs; it never selects jobs.
func ObserveWorkloadProcessDescendants(pid int, sockets bool) (WorkloadObservation, error) {
	if pid <= 1 {
		return WorkloadObservation{}, Fault("invalid_arguments", "workload observation requires --pid greater than 1")
	}
	if runtime.GOOS != "linux" {
		return WorkloadObservation{}, workloadObservationUnavailable()
	}
	return observeWorkloadDescendantsAt("/proc", pid, sockets, nil)
}
