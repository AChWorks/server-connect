//go:build linux

package sc

// v9 is a deliberately unavailable general-host Apply: it is the strict
// persistence/recovery owner for one routed kernel-policy experiment. Its
// only current mutator entry is the explicit isolated-netns kernel QA. No
// installed operator CLI can enable routed traffic through this subtype.
// Route and native effects MUST share this same durable parent with ingress,
// core, and their independently selected rollback.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	hostRouteJournalVersion = 9
	hostRouteJournalIntent  = "host_native_policy_preparation_v1"
)

type hostRouteStage struct {
	State        string `json:"state"`
	PolicySHA256 string `json:"policy_sha256"`
}

type hostRouteJournal struct {
	hostCoreJournal
	Route hostRouteStage `json:"route"`
}

// Check v8 core/native ownership with its native policy deliberately absent;
// v9 subsequently verifies every real policy object separately. This avoids
// changing the exact strict v7/v8 journal schema or granting those subtypes
// new native policy authority after an upgrade.
func (r hostRouteJournal) coreWithoutPolicy() hostCoreJournal {
	core := r.hostCoreJournal
	core.Version, core.Intent = hostCoreJournalVersion, hostCoreJournalIntent
	core.Native.NFT = smartTUNNativeObject{Stage: "planned"}
	core.Native.NFTCount = 0
	core.Native.NFTHandle = 0
	core.Native.NFTObjects = [24]smartTUNNativeNFTIdentity{}
	core.Native.StopReason = ""
	core.Native.StartupVerified = false
	core.Native.IPv4.Rule = smartTUNNativeObject{Stage: "planned"}
	core.Native.IPv4.Route = smartTUNNativeObject{Stage: "planned"}
	core.Native.IPv4.Fallback = smartTUNNativeObject{Stage: "planned"}
	core.Native.IPv6.Rule = smartTUNNativeObject{Stage: "planned"}
	core.Native.IPv6.Route = smartTUNNativeObject{Stage: "planned"}
	core.Native.IPv6.Fallback = smartTUNNativeObject{Stage: "planned"}
	return core
}

func hostRouteNoEffects(n smartTUNNativeLedger) bool {
	if n.NFT.Stage != "planned" || n.NFTCount != 0 || n.NFTHandle != 0 ||
		n.NFTObjects != ([24]smartTUNNativeNFTIdentity{}) || n.StopReason != "" {
		return false
	}
	for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		for _, o := range []smartTUNNativeObject{f.Rule, f.Route, f.Fallback} {
			if o.Stage != "planned" || o.SHA256 != "" {
				return false
			}
		}
	}
	return true
}
func hostRouteOffEffects(n smartTUNNativeLedger) bool {
	if n.NFT.Stage != "removed" || n.LinkStage != "removed" {
		return false
	}
	for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		for _, o := range []smartTUNNativeObject{f.Rule, f.Route, f.Fallback} {
			want := "removed"
			if f.Address == "" {
				want = "planned"
			}
			if o.Stage != want {
				return false
			}
		}
	}
	return true
}
func validateHostRouteJournal(r hostRouteJournal) error {
	bad := func() error {
		return activationJournalError("host policy operation identity, progress or receipt invalid")
	}
	if r.Version != hostRouteJournalVersion || r.Intent != hostRouteJournalIntent ||
		validateHostCoreJournal(r.coreWithoutPolicy()) != nil || !journalHex64.MatchString(r.Route.PolicySHA256) {
		return bad()
	}
	program, err := nativeNFTCreateJSON(r.nativeView())
	if err != nil || sha256Hex(program) != r.Route.PolicySHA256 {
		return bad()
	}
	n := r.Native
	if n.DNSResolverIPv4 != "" || n.DNSStage != "" || n.DNSSHA256 != "" {
		return bad()
	}
	if n.StartupVerified && !r.Core.StartAttempted {
		return bad()
	}
	if n.StopReason != "" && n.StopReason != "guard" {
		return bad()
	}
	for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		for _, o := range []smartTUNNativeObject{f.Rule, f.Route, f.Fallback} {
			if !nativeObjectValid(o) || (f.Address == "" && o.Stage != "planned") {
				return bad()
			}
		}
	}
	if !nativeObjectValid(n.NFT) || n.NFTCount < 0 || n.NFTCount > len(n.NFTObjects) {
		return bad()
	}
	if n.NFT.Stage == "planned" || n.NFT.Stage == "effect_possible" {
		if n.NFTHandle != 0 || n.NFTCount != 0 || n.NFTObjects != ([24]smartTUNNativeNFTIdentity{}) {
			return bad()
		}
	} else if n.NFT.Stage == "observed" || n.NFT.Stage == "remove_requested" {
		if n.NFTHandle == 0 {
			return bad()
		}
		view := r.nativeView()
		expected := nativeNFTObjects(view)
		if n.NFTCount != len(expected) || n.NFTObjects[0].Handle != n.NFTHandle {
			return bad()
		}
		for i, obj := range expected {
			for kind, value := range obj {
				fields := value.(map[string]any)
				name, _ := fields["name"].(string)
				if kind == "rule" {
					name, _ = fields["chain"].(string)
				}
				digest, err := nativeNFTObjectHash([]map[string]any{obj}, true)
				if err != nil || n.NFTObjects[i].Handle == 0 || n.NFTObjects[i].Kind != kind || n.NFTObjects[i].Name != name || n.NFTObjects[i].SHA256 != digest {
					return bad()
				}
			}
		}
	} else if n.NFT.Stage == "removed" {
		// Retain exact historical object receipts but never allow a still-live
		// table handle to become deletion authority again after removal.
		if n.NFTCount > 0 && n.NFTObjects[0].Handle != n.NFTHandle {
			return bad()
		}
	} else {
		return bad()
	}
	switch r.Route.State {
	case "planned":
		if !hostRouteNoEffects(n) {
			return bad()
		}
	case "effect_possible":
		if !n.StartupVerified || r.Core.Stage != "active_observed" || n.LinkStage != "observed" ||
			r.Progress.Barrier.Stage != "closed" || r.Progress.Ingress.Phase != "pending" {
			return bad()
		}
	case "observed":
		if r.Core.Stage != "active_observed" || n.LinkStage != "observed" || !n.StartupVerified ||
			n.NFT.Stage != "observed" || r.Progress.Barrier.Stage != "closed" || r.Progress.Ingress.Phase != "pending" {
			return bad()
		}
		for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
			if f.Address == "" {
				continue
			}
			if f.Rule.Stage != "observed" || f.Route.Stage != "observed" || f.Fallback.Stage != "observed" {
				return bad()
			}
		}
	case "off_pending":
		if r.Core.Stage == "active_observed" && n.StopReason == "" {
			return bad()
		}
	case "removed":
		if !hostRouteOffEffects(n) || r.Core.Stage != "stopped" ||
			r.Progress.Ingress.Phase != "recovered" {
			return bad()
		}
	default:
		return bad()
	}
	if r.Progress.Ingress.Phase == "recovered" && r.Route.State != "removed" && r.Route.State != "off_pending" {
		return bad()
	}
	return nil
}

func (r hostRouteJournal) nativeView() smartTUNTrialJournal {
	return r.coreWithoutPolicy().nativeBase().nativeViewWithLedger(r.Native)
}

// Bind the actual resource ledger while preserving operation/boot/netns.
func (r hostNativeJournal) nativeViewWithLedger(n smartTUNNativeLedger) smartTUNTrialJournal {
	view := r.nativeView()
	view.Native = &n
	return view
}

func decodeHostRouteJournal(raw []byte) (hostRouteJournal, error) {
	var r hostRouteJournal
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return r, err
	}
	if err := requireExactJournalKeys(raw, map[string]bool{
		"version": true, "intent_type": true, "progress": true, "tunnel_interface": true, "native": true, "core": true, "route": true,
	}); err != nil {
		return r, err
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return r, activationJournalError("host policy parent invalid")
	}
	for _, v := range values {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, activationJournalError("null host policy parent member")
		}
	}
	if err := requireExactJournalKeys(values["route"], map[string]bool{"state": true, "policy_sha256": true}); err != nil {
		return r, err
	}
	var stage map[string]json.RawMessage
	if json.Unmarshal(values["route"], &stage) != nil || stage == nil {
		return r, activationJournalError("host policy stage invalid")
	}
	for _, v := range stage {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, activationJournalError("host policy stage contains null")
		}
	}
	// Reuse the strict legacy core/ingress/native decoder for the common
	// envelope, but a v9 policy ledger can contain route/nft observations.
	projection := make(map[string]json.RawMessage, len(values)-1)
	for k, v := range values {
		if k != "route" {
			projection[k] = v
		}
	}
	projection["version"] = json.RawMessage("8")
	projection["intent_type"] = json.RawMessage(`"host_native_core_preparation_v1"`)
	var embedded struct {
		Native smartTUNNativeLedger `json:"native"`
	}
	if json.Unmarshal(values["native"], &embedded.Native) != nil {
		return r, activationJournalError("host native policy ledger invalid")
	}
	// Native nested exact keys and types MUST be checked on the actual raw
	// document before projecting policy-free state through the v8 decoder.
	if err := strictSmartTUNNativeJSON(values["native"]); err != nil {
		return r, err
	}
	native := embedded.Native
	normalized := r
	normalized.Native = native
	normalized.Native.NFT = smartTUNNativeObject{Stage: "planned"}
	normalized.Native.NFTHandle = 0
	normalized.Native.NFTCount = 0
	normalized.Native.NFTObjects = [24]smartTUNNativeNFTIdentity{}
	normalized.Native.StartupVerified = false
	normalized.Native.StopReason = ""
	for _, f := range []*smartTUNNativeFamily{&normalized.Native.IPv4, &normalized.Native.IPv6} {
		f.Rule, f.Route, f.Fallback = smartTUNNativeObject{Stage: "planned"}, smartTUNNativeObject{Stage: "planned"}, smartTUNNativeObject{Stage: "planned"}
	}
	canonicalNative, _ := json.Marshal(normalized.Native)
	projection["native"] = canonicalNative
	projected, _ := json.Marshal(projection)
	if _, err := decodeHostCoreJournal(projected); err != nil {
		return r, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return hostRouteJournal{}, activationJournalError("host policy schema invalid")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return hostRouteJournal{}, activationJournalError("host policy trailing data")
	}
	return r, validateHostRouteJournal(r)
}

func loadHostRouteJournal(store *activationJournalDir) (hostRouteJournal, activationJournalFileIdentity, error) {
	raw, id, err := store.readJournal()
	if err != nil {
		return hostRouteJournal{}, id, err
	}
	record, err := decodeHostRouteJournal(raw)
	return record, id, err
}
func writeHostRouteJournal(store *activationJournalDir, r hostRouteJournal, old *activationJournalFileIdentity) error {
	if err := validateHostRouteJournal(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return activationJournalError("cannot encode host policy parent")
	}
	return store.writeJournal(append(raw, '\n'), old)
}
func persistHostRouteParent(store *activationJournalDir, r *hostRouteJournal, next hostRouteJournal) error {
	if store == nil || r == nil {
		return Fault("guard_unavailable", "missing host routed parent")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	observed, id, err := loadHostRouteJournal(store)
	if err != nil {
		return err
	}
	if observed != *r {
		return Fault("activation_journal_conflict", "host routed parent changed")
	}
	if err := writeHostRouteJournal(store, next, &id); err != nil {
		return err
	}
	confirmed, _, err := loadHostRouteJournal(store)
	if err != nil {
		return err
	}
	if confirmed != next {
		return Fault("activation_journal_conflict", "host routed readback mismatch")
	}
	*r = next
	return nil
}
func hostRouteCapturePersist(store *activationJournalDir, r *hostRouteJournal) hostCaptureGatePersist {
	return func(before, after hostCaptureGateProgress) error {
		if r == nil || r.Progress != before {
			return Fault("activation_journal_conflict", "host routed ingress changed")
		}
		next := *r
		next.Progress = after
		return persistHostRouteParent(store, r, next)
	}
}
func hostRouteNativePersist(store *activationJournalDir, r *hostRouteJournal) nativeTUNRecordPersist {
	return func(before, after smartTUNTrialJournal) error {
		if r == nil || !sameSmartTUNTrial(r.nativeView(), before) {
			return Fault("activation_journal_conflict", "host routed native record changed")
		}
		original := r.nativeView()
		original.Native = nil
		mutation := cloneSmartTUNTrial(after)
		mutation.Native = nil
		if original != mutation || after.Native == nil {
			return Fault("activation_journal_conflict", "host routed operation metadata changed")
		}
		next := *r
		next.Native = *after.Native
		return persistHostRouteParent(store, r, next)
	}
}
func hostRouteCoreStagePersist(store *activationJournalDir, r *hostRouteJournal, stage string) error {
	if r == nil {
		return Fault("guard_unavailable", "host routed core missing")
	}
	if err := hostRouteCoreTransition(r, stage); err != nil {
		return err
	}
	next := *r
	next.Core.Stage = stage
	if stage == "start_requested" {
		next.Core.StartAttempted = true
	}
	return persistHostRouteParent(store, r, next)
}
func hostRouteCoreTransition(r *hostRouteJournal, stage string) error {
	stages := map[string][]string{
		"planned":                     {"credential_possible", "credential_remove_requested"},
		"credential_possible":         {"credential_staged", "credential_remove_requested"},
		"credential_staged":           {"start_requested", "credential_remove_requested"},
		"start_requested":             {"active_observed", "stop_requested"},
		"active_observed":             {"stop_requested"},
		"stop_requested":              {"credential_remove_requested"},
		"credential_remove_requested": {"stopped"},
	}
	if r == nil {
		return Fault("guard_unavailable", "host routed core parent missing")
	}
	for _, valid := range stages[r.Core.Stage] {
		if valid == stage {
			return nil
		}
	}
	return Fault("activation_journal_conflict", "unsupported host routed core stage")
}
func hostRoutePhasePersist(store *activationJournalDir, r *hostRouteJournal, stage string) error {
	if r == nil {
		return Fault("guard_unavailable", "host routed operation missing")
	}
	choices := map[string][]string{
		"planned":         {"effect_possible", "off_pending"},
		"effect_possible": {"observed", "off_pending"},
		"observed":        {"off_pending"},
		"off_pending":     {"removed"},
	}
	allow := false
	for _, candidate := range choices[r.Route.State] {
		if candidate == stage {
			allow = true
		}
	}
	if !allow {
		return Fault("activation_journal_conflict", "unsupported host routed policy transition")
	}
	next := *r
	next.Route.State = stage
	if stage == "effect_possible" && next.Core.Stage == "active_observed" {
		next.Native.StartupVerified = true
	}
	if stage == "off_pending" && next.Native.StopReason == "" {
		next.Native.StopReason = "guard"
	}
	return persistHostRouteParent(store, r, next)
}
