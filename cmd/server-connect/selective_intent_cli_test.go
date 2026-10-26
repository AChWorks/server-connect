package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// This is a controlled private-journal fixture: the CLI is only permitted to
// remove a previously prepared, zero-network-effect intent with an exact ID.
func preparedSelectiveCLIFixture(t *testing.T) (*sc.Manager, string, string) {
	t.Helper()
	m, path, raw := privateStatusFixture(t)
	prepared := bytes.Replace(raw, []byte(`"phase":"uncertain"`), []byte(`"phase":"prepared"`), 1)
	prepared = bytes.Replace(prepared, []byte(`"revision":2`), []byte(`"revision":1`), 1)
	if bytes.Equal(raw, prepared) || !bytes.Contains(prepared, []byte(`"revision":1`)) {
		t.Fatal("fixture phase replacement failed")
	}
	if err := os.WriteFile(path, prepared, 0600); err != nil {
		t.Fatal(err)
	}
	return m, path, "0123456789abcdef0123456789abcdef"
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
				GuardArmed      bool   `json:"guard_armed"`
				ActivationReady bool   `json:"activation_ready"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || !envelope.OK ||
			envelope.Data.Phase != "absent" || envelope.Data.Present || envelope.Data.GuardArmed || envelope.Data.ActivationReady {
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
