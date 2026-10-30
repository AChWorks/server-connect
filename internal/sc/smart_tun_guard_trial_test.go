package sc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	started := pending
	started.CoreStartAttempted = true
	recovered := started
	recovered.Phase, recovered.Revision = "trial_recovered", 2
	precredentialRecovery := pending
	precredentialRecovery.Phase, precredentialRecovery.Revision = "trial_recovered", 2
	for _, record := range []smartTUNTrialJournal{pending, started, recovered, precredentialRecovery} {
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
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false,`, "", 1)),
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false`, `"core_start_attempted":null`, 1)),
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false`, `"core_start_attempted":"false"`, 1)),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unknown":false}`)...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"version":4}`)...),
		[]byte("[]"), []byte("null"), []byte(""), []byte("{"),
	} {
		if _, err := decodeSmartTUNTrial(bad); err == nil {
			t.Fatalf("accepted invalid persisted JSON %q", bad)
		}
	}
}

func TestSmartTUNActiveUnitWithoutDurableStartIntentCannotRemainPending(t *testing.T) {
	record := trialV4Example()
	for _, tc := range []struct {
		name                  string
		attempted             bool
		unit                  string
		credential, bootValid bool
		uptime                int64
		want                  bool
	}{
		{"unauthorized active before durable start", false, "active", true, true, 10, false},
		{"unauthorized activating before durable start", false, "activating", true, true, 10, false},
		{"legitimate active before deadline", true, "active", true, true, 10, true},
		{"legitimate activating before deadline", true, "activating", true, true, 10, true},
		{"missing credential after start", true, "active", false, true, 10, false},
		{"stopped core", true, "inactive", true, true, 10, false},
		{"failed core", true, "failed", true, true, 10, false},
		{"boot changed", true, "active", true, false, 10, false},
		{"deadline reached", true, "active", true, true, record.DeadlineUptimeSec, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record.CoreStartAttempted = tc.attempted
			got := smartTUNTrialMayRemainPending(record, tc.unit, tc.credential, tc.bootValid, tc.uptime)
			if got != tc.want {
				t.Fatalf("unsafe pending admission: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSmartTUNCredentialRecoveryNeverLosesStartIntentOnRepeatedGuardTicks(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		started, present, matches bool
		beforeStop                string
		accept                    bool
	}{
		{"journal-first SIGKILL before credentials", false, false, false, "inactive", true},
		{"crash before core start with staged credential", false, true, true, "inactive", true},
		{"started core with original credential", true, true, true, "active", true},
		{"stopped failed core with original credential", true, true, true, "failed", true},
		{"missing credential after core start, first timer", true, false, false, "active", false},
		{"missing credential after core start, next timer", true, false, false, "inactive", false},
		{"changed credential after core start, next timer", true, true, false, "inactive", false},
		{"no durable start intent but unexpected core", false, true, true, "active", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := trialV4Example()
			r.CoreStartAttempted = tc.started
			err := smartTUNTrialCredentialRecoveryCheck(r, tc.beforeStop, tc.present, tc.matches)
			if tc.accept != (err == nil) {
				t.Fatalf("unsafe credential recovery decision: accepted=%v err=%v", err == nil, err)
			}
		})
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

func TestSmartTUNClearCredentialConflictBeforeGuardDisarm(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record := trialV4Example()
		record.Phase, record.Revision = "trial_recovered", 2
		if _, err := smartTUNCredentialForCleanupLocked(store, record); err != nil {
			t.Fatalf("precredential crash must permit absent config: %v", err)
		}
		record.CoreStartAttempted = true
		if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("missing start credential must block cleanup intent: %v", err)
		}
		original := []byte("unchanged guarded credential")
		record.ConfigSHA256 = sha256Hex(original)
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, original, nil); err != nil {
			return err
		}
		identity, err := smartTUNCredentialForCleanupLocked(store, record)
		if err != nil || identity == nil {
			t.Fatalf("exact recovered credential rejected: %v", err)
		}
		// The same present credential remains valid once cleanup is durable.
		record.Phase, record.Revision = "trial_cleanup_pending", 4
		if err := writeSmartTUNTrialLocked(store, record, nil); err != nil {
			return err
		}
		journalIdentity, err := reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return err
		}
		if err := store.removeSmartTUNCredential(journalIdentity, record, identity, syscall.Fsync); err != nil {
			return err
		}
		if identity, err := smartTUNCredentialForCleanupLocked(store, record); err != nil || identity != nil {
			t.Fatalf("durable cleanup did not permit removed credential: %v", err)
		}
		// Replaying the OLD recovered phase must still refuse missing bytes.
		record.Phase, record.Revision = "trial_recovered", 2
		if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("old phase silently accepted unexplained credential loss: %v", err)
		}
		path := filepath.Join(dir, smartTUNTrialConfigFile)
		if err := os.WriteFile(path, []byte("changed configuration"), 0600); err != nil {
			return err
		}
		for _, phase := range []string{"trial_recovered", "trial_cleanup_pending"} {
			record.Phase = phase
			if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
				t.Fatalf("phase %s accepted replaced credential: %v", phase, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The installed product API is narrower than the offline compiler. It only
// admits the exact IPv4 QA fixture, or its one explicit synthetic IPv6
// extension; no untrusted public prefix or arbitrary host can be applied.
func TestSmartTUNTrialFixtureScopeRejectsPartialAndBroaderIPv6(t *testing.T) {
	base := func() SmartTUNCandidateOptions {
		return SmartTUNCandidateOptions{
			TunnelInterface: "sctunqa0", UnderlayInterface: "scqaedge0",
			TunnelIPv4: "172.31.99.1/30", DomesticCIDRs: []string{"5.22.0.10/32"},
			ProtectedCIDRs: []string{"10.254.72.0/30"},
		}
	}
	dual := func() SmartTUNCandidateOptions {
		o := base()
		o.TunnelIPv6 = "fd73:99::1/64"
		o.DomesticIPv6CIDRs = []string{"2001:db8:5::/64"}
		o.IPv6Exceptions = []SmartTUNCIDRException{
			{CIDR: "2001:db8:5::10/128", Via: "vpn"},
			{CIDR: "2001:db8:8::9/128", Via: "direct"},
		}
		return o
	}
	if !smartTUNTrialFixturePolicySupported(base()) || !smartTUNTrialFixturePolicySupported(dual()) {
		t.Fatal("exact disposable IPv4 / dual-stack fixtures were refused")
	}
	for _, tc := range []struct {
		name string
		edit func(*SmartTUNCandidateOptions)
	}{
		{"missing IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "" }},
		{"missing IPv6 domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = nil }},
		{"extra IPv6 domestic", func(o *SmartTUNCandidateOptions) {
			o.DomesticIPv6CIDRs = append(o.DomesticIPv6CIDRs, "2001:db8:9::/64")
		}},
		{"wrong IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "fd73:98::1/64" }},
		{"public IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "2001:db8:ffff::1/64" }},
		{"missing VPN override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions = o.IPv6Exceptions[1:] }},
		{"missing Direct override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions = o.IPv6Exceptions[:1] }},
		{"wrong VPN override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions[0].CIDR = "2001:db8:5::11/128" }},
		{"swapped override precedence", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions[0], o.IPv6Exceptions[1] = o.IPv6Exceptions[1], o.IPv6Exceptions[0]
		}},
		{"protected IPv6 stranger", func(o *SmartTUNCandidateOptions) { o.ProtectedIPv6CIDRs = []string{"2001:db8:ffff::42/128"} }},
		{"foreign IPv4 exception", func(o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "8.8.8.8/32", Via: "direct"}}
		}},
		{"extra IPv4 Direct", func(o *SmartTUNCandidateOptions) { o.DomesticCIDRs = append(o.DomesticCIDRs, "8.8.8.8/32") }},
		{"different underlay", func(o *SmartTUNCandidateOptions) { o.UnderlayInterface = "enp1s0" }},
		{"domain sniff", func(o *SmartTUNCandidateOptions) {
			o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.com", Via: "vpn"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := dual()
			tc.edit(&o)
			if smartTUNTrialFixturePolicySupported(o) {
				t.Fatal("broadened real product TUN trial fixture")
			}
		})
	}
	o := base()
	o.TunnelIPv6 = "fd73:99::1/64"
	if smartTUNTrialFixturePolicySupported(o) {
		t.Fatal("partially specified IPv6 fixture accepted")
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
