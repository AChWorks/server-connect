//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func hostNativeExample() hostNativeJournal {
	capture := hostCaptureJournalExample().Progress
	op := capture.Ingress.OperationID
	return hostNativeJournal{
		Version: hostNativeJournalVersion, Intent: hostNativeJournalIntent,
		Progress: capture, TunnelInterface: "sctunv70",
		Native: smartTUNNativeLedger{
			Version: 1, NamespaceDev: capture.Ingress.NamespaceDev, NamespaceIno: capture.Ingress.NamespaceIno,
			UnderlayIndex: capture.Ingress.UnderlayIndex, LinkStage: "planned",
			IPv4:    nativeTUNPlannedFamily("172.31.99.1/30", nativeTUNTable4),
			IPv6:    nativeTUNPlannedFamily("", nativeTUNTable6),
			NFTName: "scnt_" + op, NFT: smartTUNNativeObject{Stage: "planned"},
		},
	}
}

func TestHostNativeParentStrictSchemaAndPhaseGates(t *testing.T) {
	record := hostNativeExample()
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeHostNativeJournal(raw)
	if err != nil || parsed != record {
		t.Fatalf("valid v7 journal rejected: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"version":7`, `"version":7,"Version":7`, 1),
		strings.Replace(string(raw), `"native":{`, `"native":{"unknown":1,`, 1),
		strings.Replace(string(raw), `"native":{`, `"native":null,`, 1),
		strings.Replace(string(raw), `"progress":{`, `"PROGRESS":{},"progress":{`, 1),
		strings.Replace(string(raw), `"link_stage":"planned"`, `"link_stage":"observed"`, 1),
		strings.Replace(string(raw), `"tunnel_interface":"sctunv70"`, `"tunnel_interface":"scing0"`, 1),
		string(raw) + " {}",
	} {
		if _, err := decodeHostNativeJournal([]byte(bad)); err == nil {
			t.Fatalf("invalid parent accepted: %s", bad)
		}
	}
	for _, modify := range []func(*hostNativeJournal){
		func(r *hostNativeJournal) { r.Native.UnderlayIndex++ },
		func(r *hostNativeJournal) { r.Native.NamespaceIno++ },
		func(r *hostNativeJournal) { r.Native.NFT.Stage = "observed" },
		func(r *hostNativeJournal) { r.Native.IPv4.Rule.Stage = "effect_possible" },
		func(r *hostNativeJournal) { r.Native.IPv6.Address = "fd73:99::1/64" },
		func(r *hostNativeJournal) { r.Native.StartupVerified = true },
		func(r *hostNativeJournal) { r.Progress.Barrier.Stage = "closed" },
		func(r *hostNativeJournal) { r.Progress.Ingress.Phase = "recovered" },
	} {
		modified := record
		modify(&modified)
		if err := validateHostNativeJournal(modified); err == nil {
			t.Fatalf("unauthorized v7 effect accepted: %+v", modified.Native)
		}
	}
}

func TestHostNativeFullParentCASAndRecoverySelection(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	record := hostNativeExample()
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostNativeJournal(store, record, nil); err != nil {
			return err
		}
		previous := record.Progress
		next := previous
		next.Ingress.SysctlStage = "effect_possible"
		if err := hostNativeCapturePersist(store, &record)(previous, next); err != nil {
			return err
		}
		if record.Progress != next {
			return errors.New("parent did not advance after acknowledged fsync")
		}
		if ErrorCode(hostNativeCapturePersist(store, &record)(previous, next)) != "activation_journal_conflict" {
			return errors.New("stale ingress writer accepted")
		}
		observed, id, err := loadHostNativeJournal(store)
		if err != nil || observed != record {
			return errors.New("v7 full-parent readback mismatch")
		}
		swapped := observed
		swapped.Native.NamespaceIno++
		// An invalid substituted journal must fail closed without replacing it.
		raw, _ := json.Marshal(swapped)
		if err := store.writeJournal(raw, &id); err != nil {
			return err
		}
		if _, _, err := loadHostNativeJournal(store); err == nil {
			return errors.New("invalid native substitution parsed")
		}
		candidate := record
		candidate.Progress.Ingress.SysctlStage = "observed"
		if err := persistHostNativeParent(store, &record, candidate); err == nil {
			return errors.New("substituted native parent was overwritten")
		}
		stored, _, err := store.readJournal()
		if err != nil || !bytes.Equal(raw, stored) {
			return errors.New("native conflict evidence was changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	phase, err := m.pendingSmartTUNTrial()
	if err == nil || phase != "" {
		t.Fatal("invalid journal was silently admitted")
	}
}

func TestHostNativeNoPolicyLinkProgressAndStatus(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostNativeExample()
	r.Progress.Ingress.SysctlStage = "observed"
	r.Progress.Ingress.NFTStage = "observed"
	r.Progress.Ingress.NFTHandle = 77
	r.Progress.Ingress.NFTSHA256 = strings.Repeat("d", 64)
	r.Progress.Barrier.Stage = "closed"
	if err := validateHostNativeJournal(r); err != nil {
		t.Fatal(err)
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostNativeJournal(store, r, nil); err != nil {
			return err
		}
		native := r.nativeView()
		next := cloneSmartTUNTrial(native)
		next.Native.LinkStage = "create_possible"
		if err := nativeTUNAdvanceWithPersist(&native, next, hostNativeLinkPersist(store, &r)); err != nil {
			return err
		}
		if r.Native.LinkStage != "create_possible" {
			return errors.New("native intent not durably committed")
		}
		if ErrorCode(clearRecoveredHostNativeLocked(store, r.Progress.Ingress.OperationID, func() error { return nil })) != "activation_journal_conflict" {
			return errors.New("v7 pending native intent was cleared")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	selection := 0
	_, err = m.recoverGuardedTrialWithHandler("", "", func(_ *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		selection++
		if s.version != hostNativeJournalVersion || s.hostNative.Native.LinkStage != "create_possible" {
			t.Fatal("v7 pending state not independently selected")
		}
		return TrialReceipt{Phase: "read_only_selected", ExperimentOnly: true}, nil
	})
	if err != nil || selection != 1 {
		t.Fatal(err)
	}
	if v, err := m.pendingSmartTUNTrial(); err != nil || v != "host_native_pending" {
		t.Fatalf("v7 pending was invisible to lifecycle: %s %v", v, err)
	}
	status, err := m.InspectActivationJournal()
	if err != nil || !status.Present || status.ActivationReady || !status.RequiresOperatorReview || status.RecoveryVerified || status.Phase != "host_native_pending" {
		t.Fatalf("v7 status falsely claimed activation: %+v %v", status, err)
	}
	_, err = m.recoverGuardedTrialWithHandler("after-delete", "", func(*activationJournalDir, trialRecoverySelection) (TrialReceipt, error) {
		t.Fatal("legacy fault flag reached v7 recovery")
		return TrialReceipt{}, nil
	})
	if ErrorCode(err) != "invalid_arguments" {
		t.Fatalf("legacy QA bypassed strict v7 selector: %v", err)
	}
}

func TestHostNativeReservedPolicyNFTNeverAdopted(t *testing.T) {
	for _, table := range []string{"scnt_" + strings.Repeat("a", 32), "scnt_" + strings.Repeat("b", 32)} {
		rows := []map[string]any{{"table": map[string]any{"family": "ip", "name": table}}}
		if ErrorCode(hostNativeNoOwnedPolicyNFT(rows)) != "trial_resource_conflict" {
			t.Fatal("foreign native table was silently accepted")
		}
	}
	if err := hostNativeNoOwnedPolicyNFT([]map[string]any{{"table": map[string]any{"family": "ip", "name": "Docker"}}}); err != nil {
		t.Fatal(err)
	}
}
