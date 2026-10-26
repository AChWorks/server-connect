package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func stageLiveFixture(t *testing.T) (*Manager, ActivationJournalStatus, []byte) {
	t.Helper()
	m := New(privateJournalTempDir(t), "", 0)
	request := fixtureSelectiveRequest()
	staged, err := m.stageSelectiveIntentWithInspector(request, func(string, string) (HostPreflight, error) {
		return fixtureSelectiveHost(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(m.Dir, activationJournalFilename))
	if err != nil {
		t.Fatal(err)
	}
	return m, staged, data
}

func assertLiveJournalUnchanged(t *testing.T, m *Manager, wanted []byte) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(m.Dir, activationJournalFilename))
	if err != nil || !bytes.Equal(got, wanted) {
		t.Fatalf("read-only verification damaged exact private journal: %v", err)
	}
}

func TestSelectiveLiveIntentReobservesExactPreparedOperation(t *testing.T) {
	m, prepared, before := stageLiveFixture(t)
	request := fixtureSelectiveRequest()
	calls := 0
	got, err := m.verifySelectiveIntentLiveWithInspector(prepared.OperationID, prepared.Revision,
		func(endpoint, peer string) (HostPreflight, error) {
			calls++
			if endpoint != request.EndpointIP || peer != request.ManagementPeerIP {
				t.Fatalf("wrong exact bound protected paths %s / %s", endpoint, peer)
			}
			return fixtureSelectiveHost(), nil
		})
	if err != nil || calls != 2 || got.OperationID != prepared.OperationID ||
		got.Revision != 1 || got.Phase != "prepared" || !got.ReadOnly ||
		!got.ObservationsMatchStoredIntent || got.SnapshotAtomic ||
		got.ActivationReady || got.GuardArmed || got.OwnershipVerified || got.RecoveryVerified {
		t.Fatalf("unsafe or incomplete operation-specific live receipt: %+v calls=%d err=%v", got, calls, err)
	}
	assertLiveJournalUnchanged(t, m, before)
	encoded, _ := json.Marshal(got)
	for _, forbidden := range []string{request.EndpointIP, request.ManagementPeerIP,
		request.Destinations[0], "plan_sha256", "observation_sha256", "before", "intended"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("private network evidence leaked in live receipt: %s", forbidden)
		}
	}
	for _, path := range []string{"runtime.json", "proxy-auth", "state.json"} {
		if _, err := os.Lstat(filepath.Join(m.Dir, path)); !os.IsNotExist(err) {
			t.Fatalf("live check wrote product runtime %s: %v", path, err)
		}
	}
}

func TestSelectiveLiveIntentRejectsDriftAndKeepsJournal(t *testing.T) {
	cases := []struct {
		name  string
		probe func(int) (HostPreflight, error)
		want  string
		calls int
	}{
		{"stable-drift", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0","metric":789},{"dst":"192.0.2.0/24","dev":"eth0"}]`)
			return host, nil
		}, "route_plan_changed", 1},
		{"foreign-link-unsupported", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.Links = json.RawMessage(`[{"ifname":"lo"},{"ifname":"scplan0"}]`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"malformed-links", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.Links = json.RawMessage(`{"kernel_private_secret":"not-an-array"}`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"unsupported-link-alias", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.Links = json.RawMessage(`[{"ifname":"lo","altnames":"kernel_private_secret"}]`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"malformed-ipv4-routes", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.IPv4Routes = json.RawMessage(`{"kernel_private_secret":"not-an-array"}`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"unsupported-route-table-alias", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0","table":"kernel_private_secret"}]`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"malformed-ipv4-rules", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.IPv4Rules = json.RawMessage(`{"kernel_private_secret":"not-an-array"}`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"unsupported-protected-lookup", func(int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			host.Endpoint.KernelRoute = json.RawMessage(`[{"dst":"kernel_private_secret"}]`)
			return host, nil
		}, "route_plan_uncertain", 1},
		{"second-inspection-malformed-rules", func(n int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			if n == 2 {
				host.IPv6Rules = json.RawMessage(`{"kernel_private_secret":"not-an-array"}`)
			}
			return host, nil
		}, "route_plan_uncertain", 2},
		{"second-inspection-drift", func(n int) (HostPreflight, error) {
			host := fixtureSelectiveHost()
			if n == 2 {
				host.IPv4Routes = json.RawMessage(`[{"dst":"default","dev":"eth0","metric":789},{"dst":"192.0.2.0/24","dev":"eth0"}]`)
			}
			return host, nil
		}, "route_plan_changed", 2},
		{"first-inspection-failed", func(int) (HostPreflight, error) {
			return HostPreflight{}, errors.New("private-target-secret")
		}, "route_plan_uncertain", 1},
		{"second-inspection-failed", func(n int) (HostPreflight, error) {
			if n == 2 {
				return HostPreflight{}, errors.New("private-target-secret")
			}
			return fixtureSelectiveHost(), nil
		}, "route_plan_uncertain", 2},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			m, staged, before := stageLiveFixture(t)
			calls := 0
			receipt, err := m.verifySelectiveIntentLiveWithInspector(staged.OperationID, 1,
				func(string, string) (HostPreflight, error) {
					calls++
					return tt.probe(calls)
				})
			if ErrorCode(err) != tt.want || calls != tt.calls ||
				receipt != (SelectiveIntentLiveCheck{}) ||
				(err != nil && (strings.Contains(err.Error(), "private-target-secret") ||
					strings.Contains(err.Error(), "kernel_private_secret") ||
					strings.Contains(err.Error(), fixtureSelectiveRequest().EndpointIP) ||
					strings.Contains(err.Error(), fixtureSelectiveRequest().ManagementPeerIP))) {
				t.Fatalf("failure was accepted/leaked: %+v, calls=%d err=%v", receipt, calls, err)
			}
			assertLiveJournalUnchanged(t, m, before)
		})
	}
}

func TestSelectiveLiveIntentRejectsWrongStaleUncertainGenericMissing(t *testing.T) {
	m, staged, before := stageLiveFixture(t)
	calls := 0
	inspect := func(string, string) (HostPreflight, error) {
		calls++
		return fixtureSelectiveHost(), nil
	}
	for _, tc := range []struct {
		id   string
		rev  uint64
		want string
	}{
		{staged.OperationID, 0, "invalid_arguments"},
		{staged.OperationID, 2, "invalid_arguments"},
		{"bad-id", 1, "invalid_arguments"},
		{strings.Repeat("0", 32), 1, "activation_journal_conflict"},
	} {
		if _, err := m.verifySelectiveIntentLiveWithInspector(tc.id, tc.rev, inspect); ErrorCode(err) != tc.want {
			t.Fatalf("wrong/stale intent accepted: %+v err=%v", tc, err)
		}
	}
	if calls != 0 {
		t.Fatal("wrong identity caused native network inspection")
	}
	assertLiveJournalUnchanged(t, m, before)
	uncertain, err := m.markActivationJournalUncertain(staged.OperationID, 1)
	if err != nil {
		t.Fatal(err)
	}
	uncertainBytes, _ := os.ReadFile(filepath.Join(m.Dir, activationJournalFilename))
	if _, err := m.verifySelectiveIntentLiveWithInspector(uncertain.OperationID, 1, inspect); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("UNCERTAIN was rechecked as prepared: %v", err)
	}
	assertLiveJournalUnchanged(t, m, uncertainBytes)
	if calls != 0 {
		t.Fatal("uncertain intent caused native inspection")
	}
	generic := New(privateJournalTempDir(t), "", 0)
	record, err := prepareFixtureJournal(generic)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := generic.verifySelectiveIntentLiveWithInspector(record.OperationID, 1, inspect); ErrorCode(err) != "activation_journal_conflict" {
		t.Fatalf("generic PREPARED became selective ownership: %v", err)
	}
	if calls != 0 {
		t.Fatal("generic intent caused inspection")
	}
	missing := New(privateJournalTempDir(t), "", 0)
	if _, err := missing.verifySelectiveIntentLiveWithInspector(staged.OperationID, 1, inspect); ErrorCode(err) != "activation_journal_missing" {
		t.Fatalf("missing journal reported as live: %v", err)
	}
}

func TestSelectiveLiveIntentRefusesTamperedEvidencePreservingBytes(t *testing.T) {
	m, staged, _ := stageLiveFixture(t)
	path := filepath.Join(m.Dir, activationJournalFilename)
	initial, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// An extra root property must not become a supported future variant.
	changed := bytes.Replace(initial, []byte(`"changes":`), []byte(`"unknown":true,"changes":`), 1)
	if bytes.Equal(initial, changed) {
		t.Fatal("invalid fixture did not modify journal")
	}
	if err := os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	if _, err := m.verifySelectiveIntentLiveWithInspector(staged.OperationID, 1,
		func(string, string) (HostPreflight, error) { calls++; return fixtureSelectiveHost(), nil }); ErrorCode(err) != "activation_journal_invalid" || calls != 0 {
		t.Fatalf("invalid typed record accepted or inspected: calls=%d err=%v", calls, err)
	}
	assertLiveJournalUnchanged(t, m, changed)
}

func TestSelectiveLiveIntentHoldsManagerLockAcrossBothSnapshots(t *testing.T) {
	m, staged, _ := stageLiveFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	verified := make(chan error, 1)
	go func() {
		_, err := m.verifySelectiveIntentLiveWithInspector(staged.OperationID, 1,
			func(string, string) (HostPreflight, error) {
				select {
				case <-entered:
				default:
					close(entered)
					<-release
				}
				return fixtureSelectiveHost(), nil
			})
		verified <- err
	}()
	<-entered
	// Deterministically prove the exact shared Manager .lock is held while
	// the first kernel observation is blocked, independent of goroutine
	// scheduling of the competing mutation.
	lockFD, err := os.OpenFile(filepath.Join(m.Dir, ".lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lockFD.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) {
		if err == nil {
			_ = syscall.Flock(int(lockFD.Fd()), syscall.LOCK_UN)
		}
		_ = lockFD.Close()
		t.Fatalf("live reinspection did not hold Manager lock: %v", err)
	}
	_ = lockFD.Close()
	result := make(chan error, 1)
	other := New(m.Dir, "", 0)
	go func() {
		_, err := other.AbandonSelectiveIntent(staged.OperationID, 1)
		result <- err
	}()
	// A competing manager cannot win journal mutation while the verification
	// holds the lock, regardless of its scheduling order.
	select {
	case err := <-result:
		t.Fatalf("abandon bypassed the observer's journal lock: %v", err)
	default:
	}
	close(release)
	if err := <-verified; err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, activationJournalFilename)); !os.IsNotExist(err) {
		t.Fatalf("abandoned prepared journal retained: %v", err)
	}
}

func TestSelectiveLiveIntentParallelReadersShareExactReceiptNotGlobalState(t *testing.T) {
	m, staged, _ := stageLiveFixture(t)
	var group sync.WaitGroup
	results := make(chan SelectiveIntentLiveCheck, 4)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			newManager := New(m.Dir, "", 0)
			check, err := newManager.verifySelectiveIntentLiveWithInspector(staged.OperationID, 1,
				func(string, string) (HostPreflight, error) { return fixtureSelectiveHost(), nil })
			results <- check
			errs <- err
		}()
	}
	group.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for receipt := range results {
		if receipt.OperationID != staged.OperationID || !receipt.ObservationsMatchStoredIntent {
			t.Fatalf("live receipt mismatched exact operation: %+v", receipt)
		}
	}
}
