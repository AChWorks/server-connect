package sc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func trialV4Example() smartTUNTrialJournal {
	return smartTUNTrialJournal{
		Version: smartTUNTrialVersion, Revision: 1, OperationID: strings.Repeat("a", 32),
		IntentType: smartTUNTrialIntent, Phase: "trial_pending", CreatedUnix: 1760000000,
		BootID: "11111111-2222-3333-4444-555555555555", DeadlineUptimeSec: 12345,
		ProfileID: "0123456789abcdef", EndpointIP: "10.254.72.2", ManagementPeerIP: "10.254.72.2",
		TunnelInterface: "sctunqa0", UnderlayInterface: "scqaedge0",
		ConfigSHA256: strings.Repeat("1", 64), BaselineSHA256: strings.Repeat("2", 64),
	}
}

func TestSmartTUNJournalCanonicalPhasesAndMinimalReceipt(t *testing.T) {
	pending := trialV4Example()
	for _, record := range []smartTUNTrialJournal{pending, func() smartTUNTrialJournal {
		pending.Phase, pending.Revision = "trial_recovered", 2
		return pending
	}()} {
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeSmartTUNTrial(raw)
		if err != nil || decoded != record {
			t.Fatalf("valid v4 record: %v", err)
		}
		receipt := smartTUNReceipt(record, record.Phase == "trial_pending", record.Phase == "trial_recovered")
		if receipt.ActivationReady || receipt.VPNVerified || !receipt.ExperimentOnly ||
			receipt.RecoveryVerified != (record.Phase == "trial_recovered") {
			t.Fatalf("unverified production readiness: %+v", receipt)
		}
	}
}

func TestSmartTUNJournalInvalidResourceIdentityAndPhaseRejected(t *testing.T) {
	cases := []struct {
		name string
		edit func(*smartTUNTrialJournal)
	}{
		{"future version", func(r *smartTUNTrialJournal) { r.Version = 5 }},
		{"legacy version collision", func(r *smartTUNTrialJournal) { r.Version = 3 }},
		{"unknown intent", func(r *smartTUNTrialJournal) { r.IntentType = "route" }},
		{"wrong pending revision", func(r *smartTUNTrialJournal) { r.Revision = 2 }},
		{"recovered with pending revision", func(r *smartTUNTrialJournal) { r.Phase = "trial_recovered" }},
		{"unverified active state", func(r *smartTUNTrialJournal) { r.Phase = "active_verified" }},
		{"bad operation", func(r *smartTUNTrialJournal) { r.OperationID = "not-an-id" }},
		{"bad profile", func(r *smartTUNTrialJournal) { r.ProfileID = "user-name" }},
		{"bad boot", func(r *smartTUNTrialJournal) { r.BootID = "different" }},
		{"deadline absent", func(r *smartTUNTrialJournal) { r.DeadlineUptimeSec = 0 }},
		{"unsafe interface", func(r *smartTUNTrialJournal) { r.TunnelInterface = "../x" }},
		{"overlapping interfaces", func(r *smartTUNTrialJournal) { r.UnderlayInterface = "sctunqa0" }},
		{"loopback underlay", func(r *smartTUNTrialJournal) { r.UnderlayInterface = "lo" }},
		{"DNS endpoint", func(r *smartTUNTrialJournal) { r.EndpointIP = "example.org" }},
		{"loopback endpoint", func(r *smartTUNTrialJournal) { r.EndpointIP = "127.0.0.1" }},
		{"multicast management", func(r *smartTUNTrialJournal) { r.ManagementPeerIP = "224.0.0.1" }},
		{"linklocal", func(r *smartTUNTrialJournal) { r.EndpointIP = "169.254.1.2" }},
		{"bad hash", func(r *smartTUNTrialJournal) { r.BaselineSHA256 = "00" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := trialV4Example()
			tc.edit(&record)
			raw, _ := json.Marshal(record)
			if _, err := decodeSmartTUNTrial(raw); err == nil {
				t.Fatal("invalid persisted operation accepted")
			}
		})
	}
}

func TestSmartTUNJournalRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	raw, _ := json.Marshal(trialV4Example())
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), []byte(" {}")...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unknown":false}`)...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"version":4}`)...),
		[]byte("[]"), []byte("null"), []byte(""), []byte("{"),
	} {
		if _, err := decodeSmartTUNTrial(bad); err == nil {
			t.Fatalf("accepted invalid persisted JSON %q", bad)
		}
	}
}

func TestSmartTUNPendingBlocksGenericStatusAndLegacyControl(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	if phase, err := m.pendingSmartTUNTrial(); err != nil || phase != "" {
		t.Fatalf("absent journal changed status: %q %v", phase, err)
	}
	raw, _ := json.Marshal(trialV4Example())
	if err := os.WriteFile(filepath.Join(dir, activationJournalFilename), raw, 0600); err != nil {
		t.Fatal(err)
	}
	phase, err := m.pendingSmartTUNTrial()
	if err != nil || phase != "trial_pending" {
		t.Fatalf("cannot recognize pending trial: %q %v", phase, err)
	}
	status, err := m.statusWithService(func() (string, error) {
		t.Fatal("generic status must not inspect proxy and claim Direct while TUN trial pending")
		return "", nil
	}, func() error { t.Fatal("must not verify unrelated proxy unit"); return nil })
	if ErrorCode(err) != "guard_pending" || status.Observed != "smart_tun_trial_pending" ||
		status.Health != "guarded_trial_unconfirmed" {
		t.Fatalf("false Direct status while guarded TUN pending: %+v %v", status, err)
	}
	if err := m.withLock(func() error {
		return m.connectLocked(func() (string, error) {
			t.Fatal("must not activate Proxy Only during TUN trial")
			return "inactive", nil
		})
	}); ErrorCode(err) != "guard_pending" {
		t.Fatalf("proxy Connect not blocked: %v", err)
	}
	if err := m.Select("0123456789abcdef"); ErrorCode(err) != "guard_pending" {
		t.Fatalf("profile Select not blocked: %v", err)
	}
}

func TestSmartTUNPendingRejectsCorruptAndUntrustedLocalJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, activationJournalFilename)
	if err := os.WriteFile(path, []byte(`{"version":4}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pendingSmartTUNTrial(); err == nil {
		t.Fatal("accepted truncated v4 journal")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pendingSmartTUNTrial(); err == nil {
		t.Fatal("accepted untrusted symlink journal")
	}
}

func TestSmartTUNTrialRefusesNoninstalledContextBeforeAnySystemctl(t *testing.T) {
	m := New(t.TempDir(), DefaultCore, DefaultPort)
	_, err := m.BeginSmartTUNTrial(SmartTUNCandidateOptions{}, "", 600, "")
	if ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("trial on arbitrary state directory did not fail closed: %v", err)
	}
}

// Existing foreign nftables owners must be in the protected baseline, not
// silently rejected, stripped, ignored or treated as product-owned. The
// counter normalization from the native PR #66 preflight remains relevant.
func TestSmartTUNSnapshotIncludesPreexistingNftablesOwners(t *testing.T) {
	firewall, err := decodeNFTSnapshot([]byte(exampleNFT))
	if err != nil || firewall.ObjectCount == 0 {
		t.Fatalf("invalid foreign firewall fixture: %+v %v", firewall, err)
	}
	host := driftFixture()
	host.Mode = "observation_with_nftables"
	host.Firewall = &firewall
	before, err := smartTUNTrialSnapshot(host)
	if err != nil || !journalHex64.MatchString(before) {
		t.Fatalf("complete foreign-owner guest snapshot rejected: %v", err)
	}
	trafficOnly := strings.Replace(exampleNFT, `"packets":12`, `"packets":2000`, 1)
	trafficOnly = strings.Replace(trafficOnly, `"bytes":8192`, `"bytes":500000`, 1)
	trafficObservation, err := decodeNFTSnapshot([]byte(trafficOnly))
	if err != nil {
		t.Fatal(err)
	}
	host.Firewall = &trafficObservation
	unchanged, err := smartTUNTrialSnapshot(host)
	if err != nil || unchanged != before {
		t.Fatalf("traffic-only counters caused false firewall baseline drift: %v", err)
	}
	foreignMutation := strings.Replace(exampleNFT, "8.8.8.8", "9.9.9.9", 1)
	mutated, err := decodeNFTSnapshot([]byte(foreignMutation))
	if err != nil {
		t.Fatal(err)
	}
	host.Firewall = &mutated
	changed, err := smartTUNTrialSnapshot(host)
	if err != nil || changed == before {
		t.Fatalf("foreign firewall rule drift was not detected: %v", err)
	}
	host.Firewall = nil
	if _, err := smartTUNTrialSnapshot(host); err == nil {
		t.Fatal("accepted missing native firewall evidence")
	}
}
