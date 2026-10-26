package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// This fixture is a COMPLETE unarmed v1 Selective record, not a generic
// PREPARED shape mislabeled through phase/revision editing. Construct the
// digest independently to verify the saved plan binding contract.
func preparedSelectiveCLIFixture(t *testing.T) (*sc.Manager, string, string) {
	t.Helper()
	m, path, _ := privateStatusFixture(t)
	const id = "0123456789abcdef0123456789abcdef"
	const endpoint = "198.51.100.1"
	const peer = "198.51.100.2"
	const device = "scplan0"
	const table = 20000
	const observed = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	route := sc.PlannedRoute{Family: "ipv4", Destination: "8.8.8.0/24", Table: table, Device: device}
	rule := sc.PlannedRule{Family: "ipv4", Destination: "8.8.8.0/24", Priority: 30000, Table: table}
	routes, rules := []sc.PlannedRoute{route}, []sc.PlannedRule{rule}
	planData, err := json.Marshal(struct {
		Endpoint, Peer, Device string
		Table                  int
		Routes                 []sc.PlannedRoute
		Rules                  []sc.PlannedRule
		Observed               string
	}{endpoint, peer, device, table, routes, rules, observed})
	if err != nil {
		t.Fatal(err)
	}
	planSHA := fmt.Sprintf("%x", sha256.Sum256(planData))
	payload, err := json.Marshal(map[string]any{
		"version": 1, "revision": 1, "operation_id": id,
		"phase": "prepared", "created_unix": 1760000000,
		"observation_sha256": observed, "plan_sha256": planSHA,
		"intent_type": "unarmed_selective_v1",
		"selective": map[string]any{
			"endpoint": endpoint, "management_peer": peer,
			"tunnel_interface": device, "route_table": table,
		},
		"changes": []any{
			map[string]any{"kind": "route", "key": "ipv4:8.8.8.0/24:table20000", "before": nil, "intended": route, "stage": "intent_recorded"},
			map[string]any{"kind": "rule", "key": "ipv4:30000", "before": nil, "intended": rule, "stage": "intent_recorded"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	status, err := m.InspectActivationJournal()
	if err != nil || status.OperationID != id || status.Phase != "prepared" || status.ResourceCount != 2 {
		t.Fatalf("fixture is not a valid selective journal: %+v %v", status, err)
	}
	return m, path, id
}

func TestSelectiveIntentCLIAbandonPreparedOnly(t *testing.T) {
	m, path, id := preparedSelectiveCLIFixture(t)
	for _, args := range [][]string{
		{"selective-abandon-intent", "--operation-id", strings.Repeat("0", 32), "--revision", "1"},
		{"selective-abandon-intent", "--operation-id", id, "--revision", "2"},
		{"selective-abandon-intent", "--operation-id", id, "--revision", "0"},
		{"selective-abandon-intent", "--operation-id", id, "--revision", "1", "unexpected"},
	} {
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
		if code == 0 || stderr != "" || !strings.Contains(stdout, `"ok":false`) ||
			strings.Contains(stdout, `"guard_armed":true`) || strings.Contains(stdout, `"data"`) {
			t.Fatalf("unverified/stale abandon had data or succeeded: %d %s %s", code, stdout, stderr)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("invalid request changed evidence: %v", err)
		}
	}
	{
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
			return run(true, m, []string{"selective-abandon-intent", "--operation-id", id, "--revision", "1"})
		})
		if code != 0 || stderr != "" {
			t.Fatalf("exact abandonment failed: %d %s %s", code, stdout, stderr)
		}
		var envelope struct {
			OK   bool `json:"ok"`
			Data struct {
				Phase           string `json:"phase"`
				Present         bool   `json:"present"`
				OperationID     string `json:"operation_id"`
				Revision        uint64 `json:"revision"`
				GuardArmed      bool   `json:"guard_armed"`
				ActivationReady bool   `json:"activation_ready"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || !envelope.OK ||
			envelope.Data.Phase != "absent" || envelope.Data.Present ||
			envelope.Data.OperationID != id || envelope.Data.Revision != 1 ||
			envelope.Data.GuardArmed || envelope.Data.ActivationReady {
			t.Fatalf("abandonment claimed route safety or did not remove intent: %+v err=%v", envelope, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("exact prepared record survived abandonment")
	}
	code, stdout, _ := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"selective-abandon-intent", "--operation-id", id, "--revision", "1"})
	})
	if code == 0 || !strings.Contains(stdout, "activation_journal_missing") {
		t.Fatal("stale replay was not rejected")
	}
}

func TestSelectiveStageCLIRejectsInvalidInputsBeforeAnyPersistentState(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	m := sc.New(filepath.Join(root, "private-state"), "", 0)
	cases := [][]string{
		{"selective-stage-intent", "--endpoint", "192.0.2.10", "--management-peer", "198.51.100.11", "--tunnel-if", "bad;iface", "--destination", "8.8.8.0/24"},
		{"selective-stage-intent", "--endpoint", "192.0.2.10", "--management-peer", "198.51.100.11", "--tunnel-if", "scint0", "--destination", "0.0.0.0/0"},
		{"selective-stage-intent", "--unexpected", "true"},
		{"selective-stage-intent", "--endpoint", "192.0.2.10", "--management-peer", "198.51.100.11", "--tunnel-if", "scint0", "--destination", "8.8.8.0/24", "extra"},
	}
	for _, args := range cases {
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
		if code != 1 || stderr != "" || !strings.Contains(stdout, `"ok":false`) ||
			!strings.Contains(stdout, "invalid_arguments") || strings.Contains(stdout, `"data"`) {
			t.Fatalf("invalid staged intent fabricated evidence: %d %s %s", code, stdout, stderr)
		}
		if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
			t.Fatalf("invalid intent touched protected state: %v", err)
		}
	}
}

func TestUncertainSelectiveCLIAbandonRefusesAllRevisions(t *testing.T) {
	m, path, original := privateStatusFixture(t)
	id := "0123456789abcdef0123456789abcdef"
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"selective-abandon-intent", "--operation-id", id, "--revision", "1"})
	})
	if code != 1 || stderr != "" || !strings.Contains(stdout, "activation_journal_conflict") || strings.Contains(stdout, `"data"`) {
		t.Fatalf("UNCERTAIN journal illegally removed or exposed: %d %s %s", code, stdout, stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("uncertain journal evidence was destroyed")
	}
}

// A legacy generic PREPARED record is syntactically valid and readable by
// activation-journal-status, but it is NOT an unarmed selective transaction.
// The command cannot be used to destroy this unrelated evidence.
func TestSelectiveCLIRefusesGenericPreparedAndPreservesBytes(t *testing.T) {
	m, path, raw := privateStatusFixture(t)
	prepared := bytes.Replace(raw, []byte(`"phase":"uncertain"`), []byte(`"phase":"prepared"`), 1)
	prepared = bytes.Replace(prepared, []byte(`"revision":2`), []byte(`"revision":1`), 1)
	if bytes.Equal(prepared, raw) {
		t.Fatal("fixture preparation failed")
	}
	if err := os.WriteFile(path, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	status, err := m.InspectActivationJournal()
	if err != nil || status.Phase != "prepared" || !status.Present {
		t.Fatal("generic journal is not valid")
	}
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"selective-abandon-intent", "--operation-id", "0123456789abcdef0123456789abcdef", "--revision", "1"})
	})
	if code == 0 || stderr != "" || !strings.Contains(stdout, "activation_journal_conflict") || strings.Contains(stdout, `"data"`) {
		t.Fatalf("generic journal wrongly treated as selective: exit=%d %s %s", code, stdout, stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, prepared) {
		t.Fatal("unrelated generic evidence was altered")
	}
}
