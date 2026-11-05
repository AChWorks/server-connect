//go:build linux

package sc

import (
	"encoding/json"
	"strings"
	"testing"
)

func hostIngressStageExample() hostIngressStage {
	return hostIngressStage{Version: 5, Intent: hostIngressStageIntent, OperationID: strings.Repeat("a", 32),
		BootID: "11111111-2222-3333-4444-555555555555", NamespaceDev: 1, NamespaceIno: 2, Deadline: 600,
		Phase: "pending", Underlay: "scing0", UnderlayIndex: 3, RawSHA256: strings.Repeat("b", 64), SysctlStage: "planned", NFTStage: "planned"}
}
func TestHostIngressJournalStrictlyBindsPendingEffectsAndReceipts(t *testing.T) {
	r := hostIngressStageExample()
	data, _ := json.Marshal(r)
	if got, err := decodeHostIngressStage(data); err != nil || got != r {
		t.Fatalf("%+v %v", got, err)
	}
	for _, change := range []func(*hostIngressStage){
		func(r *hostIngressStage) { r.Version = 4 }, func(r *hostIngressStage) { r.Intent = "" },
		func(r *hostIngressStage) { r.OperationID = "bad" }, func(r *hostIngressStage) { r.Underlay = "lo" },
		func(r *hostIngressStage) { r.UnderlayIndex = 0 }, func(r *hostIngressStage) { r.SysctlBefore = 2 },
		func(r *hostIngressStage) { r.Phase = "active" }, func(r *hostIngressStage) { r.Phase = "recovered" },
		func(r *hostIngressStage) { r.SysctlStage = "removed" }, func(r *hostIngressStage) { r.NFTHandle = 7 },
		func(r *hostIngressStage) { r.NFTStage = "observed" }, func(r *hostIngressStage) { r.NFTStage = "removed" },
		func(r *hostIngressStage) { r.NFTSHA256 = strings.Repeat("c", 64) },
	} {
		bad := r
		change(&bad)
		raw, _ := json.Marshal(bad)
		if _, err := decodeHostIngressStage(raw); err == nil {
			t.Fatalf("invalid record accepted: %+v", bad)
		}
	}
	for _, bad := range []string{
		strings.Replace(string(data), "\"version\":5", "\"version\":5,\"Version\":5", 1),
		strings.Replace(string(data), "\"sysctl_before\":0", "\"sysctl_before\":null", 1),
		string(data[:len(data)-1]) + ",\"extra\":true}",
		string(data) + " {}",
	} {
		if _, err := decodeHostIngressStage([]byte(bad)); err == nil {
			t.Fatalf("ambiguous record accepted: %s", bad)
		}
	}
	r.SysctlStage = "observed"
	r.NFTStage = "observed"
	r.NFTHandle = 7
	r.NFTSHA256 = strings.Repeat("c", 64)
	if err := validateHostIngressStage(r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "stop_requested"
	r.NFTStage = "remove_requested"
	if err := validateHostIngressStage(r); err != nil {
		t.Fatal(err)
	}
	r.Phase = "recovered"
	r.NFTStage = "removed"
	r.SysctlStage = "removed"
	if err := validateHostIngressStage(r); err != nil {
		t.Fatal(err)
	}
}
func TestHostIngressRawRequiresBothDirectionsAndRejectsHiddenEffects(t *testing.T) {
	base := "-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n"
	// An input-only NOTRACK rule is material even without OUTPUT NOTRACK.
	for _, line := range []string{
		"-A PREROUTING -p tcp -m tcp --dport 80 -j NOTRACK\n",
		"-A OUTPUT -p tcp -m tcp --sport 80 -j CT --notrack\n",
	} {
		ports, err := strictHostIngressRawPorts([]byte(base + line))
		if err != nil || len(ports) != 1 || !ports[80] {
			t.Fatalf("%v %v", ports, err)
		}
	}
	for _, line := range []string{
		"-A PREROUTING -j MARK --set-mark 1\n",
		"-A PREROUTING -p tcp -m tcp --sport 80 -j NOTRACK\n",
		"-A OUTPUT -p tcp -m tcp --dport 80 -j NOTRACK\n",
		"-A OUTPUT -p tcp -m tcp --sport 080 -j NOTRACK\n",
		"-A OUTPUT -p tcp -m tcp --sport 80:90 -j NOTRACK\n",
		"-A OUTPUT -p tcp -m tcp --sport 80 -j CT --zone 2\n",
		"-N custom\n",
		"-P OUTPUT ACCEPT\n",
	} {
		if _, err := strictHostIngressRawPorts([]byte(base + line)); err == nil {
			t.Fatalf("unverified raw rule accepted: %s", line)
		}
	}
	if ports, err := strictHostIngressRawPorts([]byte(base)); err != nil || len(ports) != 0 {
		t.Fatalf("empty default policy: %v %v", ports, err)
	}
}
func TestHostIngressNFTOwnershipRetainsForeignChildrenAndReplacements(t *testing.T) {
	r := hostIngressStageExample()
	objects := hostIngressNFTObjects(r)
	// Simulate kernel handles, preserving exact complete graph.
	for i, item := range objects {
		for _, value := range item {
			value.(map[string]any)["handle"] = json.Number(string(rune('1' + i)))
		}
	}
	observed, err := hostIngressNFTFromRows(r, objects, 42)
	if err != nil || !observed.Present || !observed.Matches || observed.Handle != 1 {
		t.Fatalf("%+v %v", observed, err)
	}
	objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": "scin_" + r.OperationID, "name": "foreign", "handle": json.Number("9")}})
	changed, err := hostIngressNFTFromRows(r, objects, 43)
	if err != nil || changed.Matches || changed.SHA256 == observed.SHA256 {
		t.Fatalf("foreign child not retained: %+v %v", changed, err)
	}
	// A same-name table with a different handle cannot satisfy the receipt.
	replacement := hostIngressNFTObjects(r)
	for i, item := range replacement {
		for _, value := range item {
			value.(map[string]any)["handle"] = json.Number(string(rune('5' + i)))
		}
	}
	changed, err = hostIngressNFTFromRows(r, replacement, 44)
	if err != nil || !changed.Matches || changed.Handle == observed.Handle || changed.SHA256 == observed.SHA256 {
		t.Fatalf("replacement identity invisible: %+v %v", changed, err)
	}
}
func TestHostIngressStageSelectionUsesTheSameManagerLock(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostIngressStageExample()
	err := m.withActivationJournalLock(nilSync, func(store *activationJournalDir) error { return writeHostIngressStage(store, r, nil) })
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		calls++
		if s.version != 5 || s.ingress != r {
			t.Fatalf("wrong dispatch: %+v", s)
		}
		return TrialReceipt{Phase: "observed"}, nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	// Legacy test fault flags cannot reinterpret a new ingress record.
	_, err = m.recoverGuardedTrialWithHandler("after-delete", "", func(*activationJournalDir, trialRecoverySelection) (TrialReceipt, error) {
		t.Fatal("legacy fault reached ingress handler")
		return TrialReceipt{}, nil
	})
	if ErrorCode(err) != "invalid_arguments" {
		t.Fatalf("unexpected fault result: %v", err)
	}
	label, err := m.pendingSmartTUNTrial()
	if err != nil || label != "host_ingress_pending" {
		t.Fatalf("hidden ingress journal: %s %v", label, err)
	}
}
func nilSync(fd int) error { return nil }
