package sc

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// WorkloadProcessIdentity is an observational procfs identity, not an
// authorization to redirect any of the process's current or future traffic.
// The kernel start time distinguishes process generations better than a bare
// PID, but is not an authenticated owner record or an atomic process handle.
type WorkloadProcessIdentity struct {
	PID            int    `json:"pid"`
	ParentPID      int    `json:"parent_pid"`
	StartTimeTicks uint64 `json:"start_time_ticks"`
	CgroupV2Path   string `json:"cgroup_v2_path"`
}

// WorkloadObservation never claims that an aaPanel job or any descendants are
// captured by the displayed ancestry/cgroup snapshot. A real selected egress
// requires a separate bound policy, kernel proof and both independent guards.
type WorkloadObservation struct {
	Mode                string                           `json:"mode"`
	ReadOnly            bool                             `json:"read_only"`
	SnapshotAtomic      bool                             `json:"snapshot_atomic"`
	AttributionVerified bool                             `json:"attribution_verified"`
	DescendantsCovered  bool                             `json:"descendants_covered"`
	TrafficPathVerified bool                             `json:"traffic_path_verified"`
	ActivationReady     bool                             `json:"activation_ready"`
	Process             WorkloadProcessIdentity          `json:"process"`
	Ancestors           []WorkloadProcessIdentity        `json:"ancestors"`
	SharesParentCgroup  bool                             `json:"shares_parent_cgroup"`
	Limitations         []string                         `json:"limitations"`
	Sockets             *WorkloadSocketEvidence          `json:"sockets,omitempty"`
	ObservedDescendants *[]WorkloadDescendantObservation `json:"observed_descendants,omitempty"`
	DescendantSurvey    string                           `json:"descendant_survey,omitempty"`
}

const workloadProcMaxBytes = 16 << 10
const workloadAncestryMaxDepth = 48

func workloadObservationUnavailable() error {
	return Fault("workload_observation_unavailable", "process/cgroup identity unavailable, changed, or unsupported; no workload selected")
}

// Read procfs only by a fixed kernel path; alternate roots are injected by
// same-package tests, never an operator-provided CLI argument. Neither
// command lines nor environments nor executable paths are accessed.
func readWorkloadProcFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, workloadObservationUnavailable()
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, workloadProcMaxBytes+1))
	if err != nil || len(data) > workloadProcMaxBytes {
		return nil, workloadObservationUnavailable()
	}
	return data, nil
}

func parseWorkloadStat(stat []byte, expectedPID int) (int, uint64, error) {
	prefix := []byte(strconv.Itoa(expectedPID) + " (")
	if !bytes.HasPrefix(stat, prefix) {
		return 0, 0, workloadObservationUnavailable()
	}
	// /proc/PID/stat encloses the unrestricted comm in parentheses. A comm can
	// itself contain ')' and spaces, so find the final delimiter, not the first.
	end := bytes.LastIndex(stat, []byte(") "))
	if end < len(prefix) || end+2 >= len(stat) {
		return 0, 0, workloadObservationUnavailable()
	}
	fields := strings.Fields(string(stat[end+2:]))
	// Fields start at kernel stat field 3 (state); field 4 is PPID and field
	// 22 is starttime, i.e. indexes 1 and 19 in this post-comm sequence.
	if len(fields) < 20 {
		return 0, 0, workloadObservationUnavailable()
	}
	// A dead/zombie/unknown task cannot safely supply an inspectable worker
	// identity. Linux may add states in future kernels; unknown fails closed.
	switch fields[0] {
	case "R", "S", "D", "T", "t", "W", "I", "P":
	default:
		return 0, 0, workloadObservationUnavailable()
	}
	ppid, e1 := strconv.Atoi(fields[1])
	start, e2 := strconv.ParseUint(fields[19], 10, 64)
	if e1 != nil || e2 != nil || ppid < 0 || start == 0 || ppid == expectedPID {
		return 0, 0, workloadObservationUnavailable()
	}
	return ppid, start, nil
}

func parseWorkloadCgroup(data []byte) (string, error) {
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	// A unique unified v2 membership is required; v1/hybrid paths must not be
	// silently interpreted as a single independently attributable job scope.
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "0::/") {
		return "", workloadObservationUnavailable()
	}
	path := strings.TrimPrefix(lines[0], "0::")
	if strings.ContainsAny(path, "\r\x00") || path == "" || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return "", workloadObservationUnavailable()
	}
	return path, nil
}

func readWorkloadProcessAt(root string, pid int) (WorkloadProcessIdentity, error) {
	if pid < 1 {
		return WorkloadProcessIdentity{}, workloadObservationUnavailable()
	}
	statPath := filepath.Join(root, strconv.Itoa(pid), "stat")
	first, e := readWorkloadProcFile(statPath)
	if e != nil {
		return WorkloadProcessIdentity{}, e
	}
	ppid, start, e := parseWorkloadStat(first, pid)
	if e != nil {
		return WorkloadProcessIdentity{}, e
	}
	cgroup, e := readWorkloadProcFile(filepath.Join(root, strconv.Itoa(pid), "cgroup"))
	if e != nil {
		return WorkloadProcessIdentity{}, e
	}
	path, e := parseWorkloadCgroup(cgroup)
	if e != nil {
		return WorkloadProcessIdentity{}, e
	}
	again, e := readWorkloadProcFile(statPath)
	if e != nil {
		return WorkloadProcessIdentity{}, e
	}
	newerPPID, newerStart, e := parseWorkloadStat(again, pid)
	if e != nil || newerPPID != ppid || newerStart != start {
		return WorkloadProcessIdentity{}, workloadObservationUnavailable()
	}
	return WorkloadProcessIdentity{PID: pid, ParentPID: ppid, StartTimeTicks: start, CgroupV2Path: path}, nil
}

func observeWorkloadAt(root string, pid int) (WorkloadObservation, error) {
	if pid <= 1 {
		return WorkloadObservation{}, Fault("invalid_arguments", "workload observation requires a positive non-init process PID")
	}
	seen := map[int]bool{}
	chain := make([]WorkloadProcessIdentity, 0, 8)
	for next := pid; next > 0; {
		if seen[next] || len(chain) >= workloadAncestryMaxDepth {
			return WorkloadObservation{}, workloadObservationUnavailable()
		}
		seen[next] = true
		identity, e := readWorkloadProcessAt(root, next)
		if e != nil {
			return WorkloadObservation{}, e
		}
		chain = append(chain, identity)
		if next == 1 || identity.ParentPID == 0 {
			break
		}
		next = identity.ParentPID
	}
	if err := recheckWorkloadAncestryAt(root, chain); err != nil {
		return WorkloadObservation{}, err
	}
	result := WorkloadObservation{
		Mode: "observation_only", ReadOnly: true, SnapshotAtomic: false,
		AttributionVerified: false, DescendantsCovered: false, TrafficPathVerified: false, ActivationReady: false,
		Process: chain[0], Ancestors: chain[1:],
		Limitations: []string{
			"Procfs ancestry and cgroup membership are non-atomic snapshots, not a reserved or authenticated job owner; PID namespace boundaries may hide parents.",
			"Shared cgroups or process ancestry alone cannot distinguish an aaPanel installation job from the panel, other root jobs, or unrelated children.",
			"No descendant lifecycle, sockets, DNS, IPv4/IPv6 flow path, outbound VPN, or guarded route is verified; no network state is changed.",
		},
	}
	if len(chain) > 1 {
		result.SharesParentCgroup = chain[0].CgroupV2Path == chain[1].CgroupV2Path
	}
	return result, nil
}

// A second full observation rejects vanished, reparented, migrated-cgroup
// or recycled PIDs. It cannot turn the non-atomic kernel snapshot into a
// permanently reserved or process-fd-authenticated workload identity.
func recheckWorkloadAncestryAt(root string, chain []WorkloadProcessIdentity) error {
	if len(chain) == 0 {
		return workloadObservationUnavailable()
	}
	for _, original := range chain {
		again, e := readWorkloadProcessAt(root, original.PID)
		if e != nil || again != original {
			return workloadObservationUnavailable()
		}
	}
	return nil
}

// ObserveWorkloadProcess provides evidence for future explicit job selection;
// it never selects a job or performs a kernel route/firewall operation.
func ObserveWorkloadProcess(pid int) (WorkloadObservation, error) {
	if pid <= 1 {
		return WorkloadObservation{}, Fault("invalid_arguments", "workload observation requires --pid greater than 1")
	}
	if runtime.GOOS != "linux" {
		return WorkloadObservation{}, Fault("workload_observation_unavailable", "process observation requires Linux procfs")
	}
	return observeWorkloadAt("/proc", pid)
}
