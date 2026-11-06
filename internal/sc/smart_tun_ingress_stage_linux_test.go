//go:build linux

package sc

import (
	"encoding/json"
	"errors"
	"strings"
	"syscall"
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

func TestHostIngressSysctlRestorationRequiresCurrentAcknowledgedOwnership(t *testing.T) {
	for _, stage := range []string{"planned", "effect_possible", "observed", "removed"} {
		for before := 0; before <= 1; before++ {
			for current := 0; current <= 1; current++ {
				restore, err := hostIngressRestoreSysctl(stage, before, current)
				wantRestore := stage == "observed" && before == 0 && current == 1
				wantError := current != before && !wantRestore
				if restore != wantRestore || (err != nil) != wantError {
					t.Fatalf("stage=%s before=%d current=%d restore=%t err=%v", stage, before, current, restore, err)
				}
			}
		}
	}
	for _, input := range [][3]int{{0, 0, 2}, {0, -1, 1}} {
		if _, err := hostIngressRestoreSysctl("observed", input[1], input[2]); err == nil {
			t.Fatal("unsupported sysctl value accepted")
		}
	}
	if _, err := hostIngressRestoreSysctl("unknown", 0, 0); err == nil {
		t.Fatal("unknown progress accepted even with matching baseline")
	}
}
func TestHostIngressExpiredStageRefusesBeforeObservationOrGuard(t *testing.T) {
	now, err := trialUptime()
	if err != nil || now <= 0 {
		t.Fatalf("uptime unavailable: %d %v", now, err)
	}
	r := hostIngressStageExample()
	r.Deadline = now
	if code := ErrorCode(hostIngressStageIntact(r)); code != "host_ingress_expired" {
		t.Fatalf("expired stage reached kernel observations: %s", code)
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return applyHostIngressStageLocked(store, &r, func() error {
			t.Fatal("expired Apply reached guard")
			return nil
		})
	})
	if ErrorCode(err) != "host_ingress_expired" {
		t.Fatalf("expired Apply returned %v", err)
	}
}
func TestHostIngressPersistenceFailureDoesNotAdvanceAcknowledgedState(t *testing.T) {
	r := hostIngressStageExample()
	previous := r
	next := r
	next.SysctlStage = "effect_possible"
	refused := errors.New("enclosing journal durability failed")
	err := advanceHostIngressStage(func(old *hostIngressStage, got hostIngressStage) error {
		if old == nil || *old != previous || got != next {
			t.Fatal("callback did not receive exact old/new states")
		}
		old.SysctlStage = "removed"
		return refused
	}, &r, next)
	if !errors.Is(err, refused) || r != previous {
		t.Fatalf("failed persistence changed memory: %+v %v", r, err)
	}
	if err := advanceHostIngressStage(nil, &r, next); err == nil || r != previous {
		t.Fatal("missing callback advanced state")
	}
	if err := persistHostIngressStage(func(*hostIngressStage, hostIngressStage) error {
		t.Fatal("invalid record reached callback")
		return nil
	}, nil, hostIngressStage{}); err == nil {
		t.Fatal("invalid record accepted")
	}
}
func TestHostIngressPersistenceCanUseOneEnclosingJournal(t *testing.T) {
	type envelope struct {
		Version int              `json:"version"`
		Owner   string           `json:"owner"`
		Ingress hostIngressStage `json:"ingress"`
	}
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	r := hostIngressStageExample()
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		persist := func(previous *hostIngressStage, next hostIngressStage) error {
			record := envelope{Version: 6, Owner: "enclosing-native-operation", Ingress: next}
			var identity *activationJournalFileIdentity
			if previous != nil {
				raw, id, err := store.readJournal()
				if err != nil {
					return err
				}
				var old envelope
				if json.Unmarshal(raw, &old) != nil || old.Version != record.Version || old.Owner != record.Owner || old.Ingress != *previous {
					return errors.New("enclosing operation conflict")
				}
				identity = &id
			}
			raw, err := json.Marshal(record)
			if err != nil {
				return err
			}
			return store.writeJournal(raw, identity)
		}
		if err := persistHostIngressStage(persist, nil, r); err != nil {
			return err
		}
		next := r
		next.SysctlStage = "effect_possible"
		if err := advanceHostIngressStage(persist, &r, next); err != nil {
			return err
		}
		raw, _, err := store.readJournal()
		if err != nil {
			return err
		}
		var got envelope
		if json.Unmarshal(raw, &got) != nil || got.Version != 6 || got.Ingress != next {
			t.Fatalf("separate v5 journal replaced enclosing operation: %s", raw)
		}
		if _, err := decodeHostIngressStage(raw); err == nil {
			t.Fatal("enclosing journal is a standalone v5 record")
		}
		stale := hostIngressStageExample()
		if err := advanceHostIngressStage(persist, &stale, next); err == nil || stale == next {
			t.Fatal("stale embedded state overwrote enclosing journal")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Real Debian 12 nftables 1.0.6 creates the table with the requested
// comment but drops that table attribute from JSON list output. Its chain and
// rule survive unchanged, including the operation-tagged rule comment.
// Allow precisely this known rendering difference, not an untrusted foreign
// graph, other nft version, missing child, changed policy or renamed table.
func TestHostIngressDebian12MissingTableCommentRendererIsExact(t *testing.T) {
	r := hostIngressStageExample()
	fresh := func() []map[string]any {
		rows := hostIngressNFTObjects(r)
		for i, item := range rows {
			for _, value := range item {
				value.(map[string]any)["handle"] = json.Number(string(rune('1' + i)))
			}
		}
		return rows
	}
	old := fresh()
	delete(old[0]["table"].(map[string]any), "comment")
	unverified, err := hostIngressNFTFromRowsWithRenderer(r, old, 123, false)
	if err != nil || !unverified.Present || unverified.Matches {
		t.Fatalf("unsupported renderer adopted: %+v %v", unverified, err)
	}
	good, err := hostIngressNFTFromRowsWithRenderer(r, old, 123, true)
	if err != nil || !good.Matches || !good.Present || good.Handle != 1 || good.Generation != 123 || good.SHA256 != unverified.SHA256 {
		t.Fatalf("pinned Debian12 graph rejected: %+v %v", good, err)
	}
	cases := []struct {
		label   string
		breakIt func([]map[string]any)
	}{
		{"extra foreign child", func(xs []map[string]any) {}},
		{"wrong underlay", func(xs []map[string]any) {
			xs[2]["rule"].(map[string]any)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = "other0"
		}},
		{"wrong kernel mark", func(xs []map[string]any) {
			xs[2]["rule"].(map[string]any)["expr"].([]any)[3].(map[string]any)["match"].(map[string]any)["right"] = json.Number("1")
		}},
		{"missing rule operation tag", func(xs []map[string]any) { delete(xs[2]["rule"].(map[string]any), "comment") }},
		{"changed table name", func(xs []map[string]any) { xs[0]["table"].(map[string]any)["name"] = "different" }},
		{"foreign table comment", func(xs []map[string]any) { xs[0]["table"].(map[string]any)["comment"] = "foreign" }},
		{"wrong hook", func(xs []map[string]any) { xs[1]["chain"].(map[string]any)["hook"] = "output" }},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			xs := fresh()
			delete(xs[0]["table"].(map[string]any), "comment")
			if tc.label == "extra foreign child" {
				xs = append(xs, map[string]any{"rule": map[string]any{"family": "inet", "table": "scin_" + r.OperationID, "chain": "ingress", "comment": "foreign", "expr": []any{map[string]any{"drop": nil}}, "handle": json.Number("4")}})
			} else {
				tc.breakIt(xs)
			}
			got, e := hostIngressNFTFromRowsWithRenderer(r, xs, 124, true)
			if e == nil && got.Matches {
				t.Fatalf("foreign graph adopted: %+v", got)
			}
		})
	}
}

func TestHostIngressMissingCommentNeedsPinnedNft106Metainfo(t *testing.T) {
	listing := func(version, release string, schema int) []byte {
		raw, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"metainfo": map[string]any{"version": version, "release_name": release, "json_schema_version": schema}}}})
		return raw
	}
	for _, tc := range []struct {
		version, release string
		schema           int
		allowed          bool
	}{
		{"1.0.6", "Lester Gooch #5", 1, true},
		{"1.1.3", "Lester Gooch #5", 1, false},
		{"1.0.6", "unknown", 1, false},
		{"1.0.6", "Lester Gooch #5", 2, false},
	} {
		if got := hostIngressLegacyMissingTableComment(listing(tc.version, tc.release, tc.schema)); got != tc.allowed {
			t.Fatalf("unsupported renderer mode: %+v got=%v", tc, got)
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), []byte(`{"nftables":[]}`), []byte(`{"nftables":[{"foo":{}}]}`)} {
		if hostIngressLegacyMissingTableComment(raw) {
			t.Fatalf("bad metainfo admitted: %s", raw)
		}
	}
}
