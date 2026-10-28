package sc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// A virtual procfs directory makes it possible to test very large directory
// enumerations without allocating a large slice or creating real processes.
// It also rejects ReadDir(0/-1), which would materialize every remaining entry.
type syntheticWorkloadProcDirReader struct {
	total        int
	position     int
	calls        int
	largestBatch int
	numeric      bool
	failOnCall   int
}

type syntheticWorkloadProcDirEntry struct {
	name string
}

func (e syntheticWorkloadProcDirEntry) Name() string { return e.name }
func (e syntheticWorkloadProcDirEntry) IsDir() bool  { return true }
func (e syntheticWorkloadProcDirEntry) Type() fs.FileMode {
	return fs.ModeDir
}
func (e syntheticWorkloadProcDirEntry) Info() (fs.FileInfo, error) {
	return nil, os.ErrNotExist // The implementation must not stat directory entries.
}

func (r *syntheticWorkloadProcDirReader) ReadDir(n int) ([]os.DirEntry, error) {
	if n <= 0 || n > workloadDescendantDirBatchSize {
		return nil, fmt.Errorf("unbounded ReadDir(%d)", n)
	}
	r.calls++
	if n > r.largestBatch {
		r.largestBatch = n
	}
	if r.failOnCall == r.calls {
		return nil, errors.New("injected directory read failure")
	}
	if r.position >= r.total {
		return nil, io.EOF
	}
	count := n
	if r.total-r.position < count {
		count = r.total - r.position
	}
	entries := make([]os.DirEntry, 0, count)
	for i := 0; i < count; i++ {
		position := r.position + i
		name := fmt.Sprintf("nonnumeric-%08d", position)
		if r.numeric {
			name = strconv.Itoa(100000 + position)
		}
		entries = append(entries, syntheticWorkloadProcDirEntry{name: name})
	}
	r.position += count
	return entries, nil
}

func TestWorkloadProcessCensusStreamsAndEnforcesAggregateDirectoryLimit(t *testing.T) {
	root := t.TempDir()
	reader := &syntheticWorkloadProcDirReader{total: workloadDescendantMaxDirEntries * 8}
	survey, err := workloadProcessCensusFromReader(root, reader)
	requireUnavailableWorkload(t, err)
	if survey != nil {
		t.Fatalf("over-limit census returned partial success: %+v", survey)
	}
	if reader.calls <= 1 || reader.largestBatch > workloadDescendantDirBatchSize ||
		reader.position != workloadDescendantMaxDirEntries+1 ||
		reader.position >= reader.total {
		t.Fatalf("directory census did not fail early with bounded batches: %+v", reader)
	}
}

func TestWorkloadProcessCensusStreamsAndEnforcesNumericPIDLimit(t *testing.T) {
	root := t.TempDir()
	reader := &syntheticWorkloadProcDirReader{total: workloadDescendantMaxProcEntries * 4, numeric: true}
	survey, err := workloadProcessCensusFromReader(root, reader)
	requireUnavailableWorkload(t, err)
	if survey != nil || reader.calls <= 1 || reader.largestBatch > workloadDescendantDirBatchSize ||
		reader.position > workloadDescendantMaxProcEntries+workloadDescendantDirBatchSize {
		t.Fatalf("numeric PID ceiling failed to reject early or leaked partial evidence: survey=%v reader=%+v", survey, reader)
	}
}

func TestWorkloadProcessCensusAcceptsExactDirectoryAndNumericBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		total   int
		numeric bool
	}{
		{"all_nonnumeric_at_total_cap", workloadDescendantMaxDirEntries, false},
		{"numeric_at_pid_cap", workloadDescendantMaxProcEntries, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &syntheticWorkloadProcDirReader{total: tc.total, numeric: tc.numeric}
			survey, err := workloadProcessCensusFromReader(t.TempDir(), reader)
			if err != nil || survey == nil || len(survey) != 0 ||
				reader.position != tc.total || reader.largestBatch > workloadDescendantDirBatchSize {
				t.Fatalf("valid streaming boundary rejected: survey=%v err=%v reader=%+v", survey, err, reader)
			}
		})
	}
}

func TestWorkloadProcessCensusRejectsPartialReaderFailure(t *testing.T) {
	reader := &syntheticWorkloadProcDirReader{total: workloadDescendantMaxDirEntries, failOnCall: 2}
	survey, err := workloadProcessCensusFromReader(t.TempDir(), reader)
	requireUnavailableWorkload(t, err)
	if survey != nil || reader.calls != 2 || reader.position != workloadDescendantDirBatchSize {
		t.Fatalf("mid-census read error was mistaken for complete survey: survey=%v reader=%+v", survey, reader)
	}
}

func TestWorkloadDescendantSecondCensusOverLimitNeverReturnsPartialEvidence(t *testing.T) {
	root := workDescendantFixture(t)
	report, err := observeWorkloadDescendantsAt(root, 200, false, func() {
		// The first census and selected-child observations succeeded.
		// Inject too many unrelated procfs entries before the second census.
		for i := 0; i <= workloadDescendantMaxDirEntries; i++ {
			name := filepath.Join(root, fmt.Sprintf("not-a-pid-%06d", i))
			if e := os.WriteFile(name, nil, 0600); e != nil {
				t.Fatal(e)
			}
		}
	})
	requireUnavailableWorkload(t, err)
	if report.Process.PID != 0 || report.ObservedDescendants != nil ||
		report.Sockets != nil || report.Mode != "" {
		t.Fatalf("failed second census exposed partial observations: %+v", report)
	}
}

func TestWorkloadProcessCensusActualDirectoryOverLimitFailsClosed(t *testing.T) {
	root := t.TempDir()
	// Real filesystem fixture exercises the production os.Open + positive
	// File.ReadDir path, rather than only the injectable reader seam.
	for i := 0; i <= workloadDescendantMaxDirEntries; i++ {
		name := filepath.Join(root, fmt.Sprintf("not-a-pid-%06d", i))
		if err := os.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	survey, err := workloadProcessCensusAt(root)
	requireUnavailableWorkload(t, err)
	if survey != nil {
		t.Fatalf("over-limit real directory yielded partial survey: %+v", survey)
	}
	if err := os.Remove(filepath.Join(root, fmt.Sprintf("not-a-pid-%06d", workloadDescendantMaxDirEntries))); err != nil {
		t.Fatal(err)
	}
	survey, err = workloadProcessCensusAt(root)
	if err != nil || survey == nil || len(survey) != 0 {
		t.Fatalf("exact-limit real directory should stream successfully: survey=%+v err=%v", survey, err)
	}
}
