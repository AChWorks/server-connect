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

func hostRouteExample(t *testing.T) hostRouteJournal {
	t.Helper()
	v8 := hostCoreLinkedExample()
	v8.Version, v8.Intent = hostRouteJournalVersion, hostRouteJournalIntent
	r := hostRouteJournal{hostCoreJournal: v8, Route: hostRouteStage{State: "planned"}}
	data, err := nativeNFTCreateJSON(r.nativeView())
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = sha256Hex(data)
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHostRouteV9ParentStrictSchemaOwnershipAndReadback(t *testing.T) {
	base := hostRouteExample(t)
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeHostRouteJournal(raw)
	if err != nil || got != base {
		t.Fatalf("v9 parent round trip failed: %v", err)
	}
	for _, changed := range []string{
		strings.Replace(string(raw), `"version":9`, `"version":8`, 1),
		strings.Replace(string(raw), `"intent_type":"host_native_policy_preparation_v1"`, `"intent_type":"host_native_core_preparation_v1"`, 1),
		strings.Replace(string(raw), `"route":{`, `"route":{"state":"planned",`, 1),
		strings.Replace(string(raw), `"route":{`, `"route":{"unknown":1,`, 1),
		strings.Replace(string(raw), `"route":{`, `"route":null,`, 1),
		strings.Replace(string(raw), `"state":"planned"`, `"state":null`, 1),
		strings.Replace(string(raw), `"policy_sha256":"`, `"policy_sha256":"123`, 1),
		strings.Replace(string(raw), `"core":{`, `"core":{"profile_id":null,`, 1),
		strings.Replace(string(raw), `"native":{`, `"native":{"startup_verified":null,`, 1),
		string(raw) + " {}",
	} {
		if _, err := decodeHostRouteJournal([]byte(changed)); err == nil {
			t.Fatalf("accepted forged v9 parent: %s", changed)
		}
	}
	// Preserve older v8/v7 decoding boundaries: neither can reinterpret a v9
	// policy-operation record after restarting/upgrading the installed binary.
	if _, err := decodeHostCoreJournal(raw); err == nil {
		t.Fatal("v9 interpreted as v8")
	}
	if _, err := decodeHostNativeJournal(raw); err == nil {
		t.Fatal("v9 interpreted as v7")
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, base, nil); err != nil {
			return err
		}
		selected, err := selectTrialRecoveryLocked(store, "", "")
		if err != nil || selected.version != hostRouteJournalVersion || selected.hostRoute != base {
			return errors.New("independent v9 recovery selector lost exact policy owner")
		}
		if _, err := selectTrialRecoveryLocked(store, "after-native-nft-effect", ""); err == nil {
			return errors.New("v4 legacy fault flags were accepted for v9 routed journal")
		}
		if err := hostRouteCoreStagePersist(store, &base, "credential_possible"); err != nil {
			return err
		}
		actual, _, err := loadHostRouteJournal(store)
		if err != nil || actual != base {
			return errors.New("v9 in-place CAS/readback changed core parent")
		}
		foreign := base
		foreign.Core.PinnedEndpoint = "9.9.9.9"
		bytesForeign, _ := json.Marshal(foreign)
		_, id, err := loadHostRouteJournal(store)
		if err != nil {
			return err
		}
		if err := store.writeJournal(bytesForeign, &id); err != nil {
			return err
		}
		next := base
		next.Core.Stage = "credential_staged"
		if ErrorCode(persistHostRouteParent(store, &base, next)) != "activation_journal_conflict" {
			return errors.New("stale v9 parent overwrote foreign concurrent update")
		}
		stored, _, err := store.readJournal()
		if err != nil || !bytes.Equal(stored, bytesForeign) {
			return errors.New("foreign journal change was erased")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostRouteV9PolicyCannotStartWithoutCoreAndJournalIntent(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostRouteExample(t)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, r, nil); err != nil {
			return err
		}
		if ErrorCode(hostRoutePhasePersist(store, &r, "effect_possible")) == "" {
			return errors.New("policy mutation permitted without Core ready and owned guard")
		}
		for _, stage := range []string{"credential_possible", "credential_staged", "start_requested", "active_observed"} {
			if err := hostRouteCoreStagePersist(store, &r, stage); err != nil {
				return err
			}
		}
		if err := hostRoutePhasePersist(store, &r, "effect_possible"); err != nil {
			return err
		}
		if !r.Native.StartupVerified || r.Route.State != "effect_possible" {
			return errors.New("v9 did not retain durable core/start policy intent")
		}
		view := r.nativeView()
		next := cloneSmartTUNTrial(view)
		next.Native.IPv4.Fallback = smartTUNNativeObject{Stage: "effect_possible"}
		if err := nativeTUNAdvanceWithPersist(&view, next, hostRouteNativePersist(store, &r)); err != nil {
			return err
		}
		reloaded, _, err := loadHostRouteJournal(store)
		if err != nil || reloaded != r || r.Native.IPv4.Fallback.Stage != "effect_possible" {
			return errors.New("v9 shared core+policy parent missed native progress")
		}
		if ErrorCode(hostRoutePhasePersist(store, &r, "observed")) == "" {
			return errors.New("partial native policy falsely marked fully verified")
		}
		if err := hostRoutePhasePersist(store, &r, "off_pending"); err != nil {
			return err
		}
		if r.Native.StopReason != "guard" {
			return errors.New("v9 off intent lost guarded stop reason")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
