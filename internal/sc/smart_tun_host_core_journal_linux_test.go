//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
	"testing"
)

func hostCoreExample() hostCoreJournal {
	r := hostNativeExample()
	r.Version, r.Intent = hostCoreJournalVersion, hostCoreJournalIntent
	return hostCoreJournal{hostNativeJournal: r, Core: hostCoreLedger{
		ProfileID: "abcdef0123456789", ConfigSHA256: strings.Repeat("a", 64),
		PinnedEndpoint: "8.8.8.8", Stage: "planned",
	}}
}

func TestHostCoreParentStrictSchemaAndComposedIdentity(t *testing.T) {
	example := hostCoreExample()
	if err := validateHostCoreJournal(example); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(example)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := decodeHostCoreJournal(raw)
	if err != nil || observed != example {
		t.Fatalf("v8 composite serialization lost parent: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(string(raw), `"version":8`, `"version":7`, 1),
		strings.Replace(string(raw), `"intent_type":"host_native_core_preparation_v1"`, `"intent_type":"host_native_link_preparation_v1"`, 1),
		strings.Replace(string(raw), `"core":{`, `"core":{"stage":"planned",`, 1),
		strings.Replace(string(raw), `"core":{`, `"core":{"unknown":true,`, 1),
		strings.Replace(string(raw), `"core":{`, `"core":null,`, 1),
		strings.Replace(string(raw), `"start_attempted":false`, `"start_attempted":null`, 1),
		strings.Replace(string(raw), `"stage":"planned"`, `"stage":"active_observed"`, 1),
		string(raw) + " {}",
	} {
		if _, err := decodeHostCoreJournal([]byte(bad)); err == nil {
			t.Fatalf("accepted forged or ambiguous host-core journal %s", bad)
		}
	}
	for _, modify := range []func(*hostCoreJournal){
		func(r *hostCoreJournal) { r.Native.NFT.Stage = "observed" },
		func(r *hostCoreJournal) { r.Core.PinnedEndpoint = "127.0.0.1" },
		func(r *hostCoreJournal) { r.Core.ConfigSHA256 = "oops" },
		func(r *hostCoreJournal) { r.Core.StartAttempted = true },
		func(r *hostCoreJournal) { r.Progress.Ingress.Phase = "recovered" },
		func(r *hostCoreJournal) { r.Core.Stage = "start_requested" },
	} {
		changed := example
		modify(&changed)
		if err := validateHostCoreJournal(changed); err == nil {
			t.Fatal("invalid host core/native stage accepted")
		}
	}
}

func TestHostCoreOneJournalCASAndStageBoundaries(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostCoreExample()
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &r, "credential_staged"); err != nil {
			return err
		}
		if r.Core.StartAttempted {
			return errors.New("start authority invented before durable systemd intent")
		}
		if ErrorCode(hostCoreAdvance(store, &r, "active_observed")) != "activation_journal_conflict" {
			return errors.New("core started without prior durable start intent")
		}
		before := r.Progress
		after := before
		after.Ingress.SysctlStage = "effect_possible"
		if err := hostCoreCapturePersist(store, &r)(before, after); err != nil {
			return err
		}
		if ErrorCode(hostCoreCapturePersist(store, &r)(before, after)) != "activation_journal_conflict" {
			return errors.New("stale v8 ingress transition overwrote newer parent")
		}
		raw, id, err := store.readJournal()
		if err != nil {
			return err
		}
		foreign := r
		foreign.Core.PinnedEndpoint = "9.9.9.9"
		data, _ := json.Marshal(foreign)
		if err := store.writeJournal(data, &id); err != nil {
			return err
		}
		next := r
		next.Core.Stage = "start_requested"
		next.Core.StartAttempted = true
		if ErrorCode(persistHostCoreParent(store, &r, next)) != "activation_journal_conflict" {
			return errors.New("forged v8 parent overwritten")
		}
		stored, _, err := store.readJournal()
		if err != nil || string(stored) != string(data) {
			return errors.New("foreign modification lost")
		}
		if len(raw) == 0 {
			return errors.New("old journal unexpectedly empty")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func hostCoreLinkedExample() hostCoreJournal {
	r := hostCoreExample()
	r.Progress.Ingress.SysctlStage = "observed"
	r.Progress.Ingress.NFTStage = "observed"
	r.Progress.Ingress.NFTHandle = 77
	r.Progress.Ingress.NFTSHA256 = strings.Repeat("c", 64)
	r.Progress.Barrier.Stage = "closed"
	r.Native.LinkStage = "observed"
	r.Native.LinkIndex = 8
	r.Native.LinkSHA256 = strings.Repeat("d", 64)
	r.Native.AddressSHA256 = strings.Repeat("e", 64)
	r.Native.IPv4.DependentSHA256 = strings.Repeat("1", 64)
	r.Native.IPv6.DependentSHA256 = strings.Repeat("2", 64)
	return r
}

func TestHostCoreStartIntentRequiresReceiptedNativeLink(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostCoreExample()
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		for _, stage := range []string{"credential_possible", "credential_staged"} {
			if err := hostCoreAdvance(store, &r, stage); err != nil {
				return err
			}
		}
		if ErrorCode(hostCoreAdvance(store, &r, "start_requested")) != "activation_journal_invalid" &&
			ErrorCode(hostCoreAdvance(store, &r, "start_requested")) != "activation_journal_conflict" {
			return errors.New("core start permitted without independently receipted TUN")
		}
		observed, _, err := loadHostCoreJournal(store)
		if err != nil || observed.Core.Stage != "credential_staged" || observed.Core.StartAttempted {
			return errors.New("rejected start modified durable core authority")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostCoreCredentialStagingAndIndependentNoStartRollback(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostCoreExample()
	secret := []byte(`{"inbounds":[],"credential":"ephemeral-test-only"}`)
	r.Core.ConfigSHA256 = sha256Hex(secret)
	stopCalls := 0
	idle := smartTUNCoreObservationExample("inactive")
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return idle, nil },
		stop: func(smartTUNTrialUnitObservation, bool, bool) error {
			stopCalls++
			return errors.New("unowned stop must not run")
		},
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		if err := hostCoreAdvance(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
			return err
		}
		// Real fsynced credential exists even if its final stage was not acknowledged.
		if err := hostCoreStopLocked(store, &r, services); err != nil {
			return err
		}
		if r.Core.Stage != "stopped" || r.Core.StartAttempted {
			return errors.New("unstarted core was given start authority")
		}
		if present, _, err := hostCoreCredentialState(store, r); err != nil || present {
			return errors.New("matching abandoned credential was not removed")
		}
		if stopCalls != 0 {
			return errors.New("unowned unit was stopped")
		}
		return hostCoreStopLocked(store, &r, services)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostCoreActiveServiceWithoutRecordedIntentFailsClosed(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostCoreExample()
	observed := smartTUNCoreObservationExample("active")
	stopCalls := 0
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		services := hostCoreRecoveryServices{observe: func() (smartTUNTrialUnitObservation, error) { return observed, nil },
			stop: func(smartTUNTrialUnitObservation, bool, bool) error { stopCalls++; return nil }}
		if ErrorCode(hostCoreStopLocked(store, &r, services)) != "trial_resource_conflict" {
			return errors.New("foreign active service adopted as ours without durable start")
		}
		if stopCalls != 0 || r.Core.Stage != "planned" {
			return errors.New("unowned active service was modified")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostCoreObservedServiceRecoveryStopsBeforeRemovingCredential(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostCoreLinkedExample()
	secret := []byte(`{"selected":"test-only"}`)
	r.Core.ConfigSHA256 = sha256Hex(secret)
	if err := validateHostCoreJournal(r); err != nil {
		t.Fatal(err)
	}
	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	calls := 0
	service := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
		stop: func(original smartTUNTrialUnitObservation, attempted, valid bool) error {
			calls++
			if !attempted || !valid {
				return errors.New("missing durable start/credential authority")
			}
			state = inactive
			return nil
		},
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostCoreJournal(store, r, nil); err != nil {
			return err
		}
		for _, stage := range []string{"credential_possible", "credential_staged"} {
			if stage == "credential_staged" {
				if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
					return err
				}
			}
			if err := hostCoreAdvance(store, &r, stage); err != nil {
				return err
			}
		}
		if err := hostCoreAdvance(store, &r, "start_requested"); err != nil {
			return err
		}
		if err := hostCoreStopLocked(store, &r, service); err != nil {
			return err
		}
		if calls != 1 || r.Core.Stage != "stopped" || !r.Core.StartAttempted {
			return errors.New("durable core start was not safely stopped")
		}
		if present, _, err := hostCoreCredentialState(store, r); err != nil || present {
			return errors.New("core secret retained after Off")
		}
		return hostCoreStopLocked(store, &r, service)
	})
	if err != nil {
		t.Fatal(err)
	}
}
