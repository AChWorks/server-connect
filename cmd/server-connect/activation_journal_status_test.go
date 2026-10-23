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

func privateStatusFixture(t *testing.T) (*sc.Manager, string, []byte) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	const secret = "customer-internal-address-198.51.100.25-do-not-print"
	payload, err := json.Marshal(map[string]any{
		"version": 1, "revision": 2,
		"operation_id":       "0123456789abcdef0123456789abcdef",
		"phase":              "uncertain",
		"created_unix":       1760000000,
		"observation_sha256": strings.Repeat("a", 64),
		"plan_sha256":        strings.Repeat("b", 64),
		"changes": []any{map[string]any{
			"kind":   "route",
			"key":    "ipv4:8.8.8.0/24:table20000",
			"before": nil,
			"intended": map[string]any{
				"family": "ipv4", "destination": "8.8.8.0/24",
				"table": 20000, "device": "scplan0",
				"operator_private_metadata": secret,
			},
			"stage": "intent_recorded",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "route-activation-journal.json")
	if err := os.WriteFile(path, append(payload, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	return sc.New(dir, "", 0), path, append(payload, '\n')
}

func TestActivationJournalStatusCLIAbsentInvalidOptionsAndRedaction(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	m := sc.New(filepath.Join(root, "private-state"), "", 0)
	code, output, stderr := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"activation-journal-status", "--unsupported"})
	})
	if code == 0 || stderr != "" || !strings.Contains(output, "invalid_arguments") {
		t.Fatalf("invalid activation-status command accepted: exit=%d out=%s stderr=%s", code, output, stderr)
	}
	if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
		t.Fatalf("invalid options unexpectedly created state directory: %v", err)
	}
	code, output, stderr = hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"activation-journal-status"})
	})
	if code != 0 || stderr != "" {
		t.Fatalf("absent intent observation failed: code=%d out=%s stderr=%s", code, output, stderr)
	}
	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			Phase                  string `json:"phase"`
			Present                bool   `json:"present"`
			ActivationReady        bool   `json:"activation_ready"`
			GuardArmed             bool   `json:"guard_armed"`
			RecoveryVerified       bool   `json:"recovery_verified"`
			HostNetworkInspected   bool   `json:"host_network_inspected"`
			RequiresOperatorReview bool   `json:"requires_operator_review"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK || resp.Data.Phase != "absent" || resp.Data.Present ||
		resp.Data.ActivationReady || resp.Data.GuardArmed ||
		resp.Data.RecoveryVerified || resp.Data.HostNetworkInspected ||
		resp.Data.RequiresOperatorReview {
		t.Fatalf("absent activation intent incorrectly advertised safety: %s", output)
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "route-activation-journal.json")); !os.IsNotExist(err) {
		t.Fatalf("read-only-network CLI fabricated intent journal: %v", err)
	}
}

func TestActivationJournalStatusCLIUncertainAndInvalidEvidence(t *testing.T) {
	m, path, original := privateStatusFixture(t)
	check := func(jsonMode bool) {
		t.Helper()
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
			return run(jsonMode, m, []string{"activation-journal-status"})
		})
		if code != 0 || stderr != "" || !strings.Contains(stdout, "uncertain") ||
			!strings.Contains(stdout, "0123456789abcdef0123456789abcdef") ||
			!strings.Contains(stdout, "requires_operator_review") {
			t.Fatalf("uncertain status invisible: code=%d out=%s err=%s", code, stdout, stderr)
		}
		for _, forbidden := range []string{"customer-internal-address", "8.8.8.0/24",
			"operator_private_metadata", "observation_sha256", "plan_sha256", `"guard_armed":true`} {
			if strings.Contains(stdout, forbidden) || strings.Contains(stderr, forbidden) {
				t.Fatalf("private journal material leaked into status: %s %s", stdout, stderr)
			}
		}
		if jsonMode {
			var body map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &body); err != nil || !bytes.Equal(body["ok"], []byte("true")) {
				t.Fatalf("uncertain JSON status invalid: %v %s", err, stdout)
			}
			var report struct {
				Phase                  string `json:"phase"`
				Present                bool   `json:"present"`
				RequiresOperatorReview bool   `json:"requires_operator_review"`
				ActivationReady        bool   `json:"activation_ready"`
				GuardArmed             bool   `json:"guard_armed"`
				RecoveryVerified       bool   `json:"recovery_verified"`
				HostNetworkInspected   bool   `json:"host_network_inspected"`
				ResourceCount          int    `json:"resource_count"`
			}
			if err := json.Unmarshal(body["data"], &report); err != nil || report.Phase != "uncertain" ||
				!report.Present || !report.RequiresOperatorReview || report.ResourceCount != 1 ||
				report.ActivationReady || report.GuardArmed || report.RecoveryVerified || report.HostNetworkInspected {
				t.Fatalf("uncertain status made false safety claims: %+v err=%v", report, err)
			}
		}
	}
	check(true)
	check(false)
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("inspection changed original journal evidence: %v", err)
	}
	corrupt := bytes.Replace(original, []byte(`"phase":"uncertain"`), []byte(`"phase":"active_verified"`), 1)
	if bytes.Equal(original, corrupt) {
		t.Fatal("failed to construct corrupt journal fixture")
	}
	if err := os.WriteFile(path, corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"activation-journal-status"})
	})
	if code == 0 || stderr != "" || !strings.Contains(stdout, "activation_journal_invalid") ||
		strings.Contains(stdout, `"data"`) || strings.Contains(stdout, "customer-internal-address") {
		t.Fatalf("invalid journal was reported as safe or exposed private data: %d %s %s", code, stdout, stderr)
	}
	preserved, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(preserved, corrupt) {
		t.Fatalf("error path changed corruption evidence: %v", err)
	}
}

func TestActivationJournalStatusMenuShowsSafeSummary(t *testing.T) {
	m, path, original := privateStatusFixture(t)
	input, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = write.Write([]byte("16\n0\n")); err != nil {
		t.Fatal(err)
	}
	_ = write.Close()
	old := os.Stdin
	os.Stdin = input
	defer func() { os.Stdin = old; _ = input.Close() }()
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return menu(m) })
	if code != 0 || stderr != "" || !strings.Contains(stdout, "Activation Journal") ||
		!strings.Contains(stdout, "uncertain") || !strings.Contains(stdout, "requires_operator_review") ||
		strings.Contains(stdout, "customer-internal-address") || strings.Contains(stdout, "8.8.8.0/24") {
		t.Fatalf("menu journal status leaked evidence or failed: %d %s %s", code, stdout, stderr)
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, original) {
		t.Fatalf("menu observation changed private journal: %v", err)
	}
}
