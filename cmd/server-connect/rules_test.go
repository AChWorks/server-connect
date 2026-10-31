package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func rulesCLIManager(t *testing.T) *sc.Manager {
	t.Helper()
	return sc.New(filepath.Join(t.TempDir(), "rules-state"), "", 0)
}
func captureRulesCommand(t *testing.T, m *sc.Manager, args ...string) (int, map[string]any, string) {
	t.Helper()
	rc, stdout, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
	var v map[string]any
	if err := json.Unmarshal([]byte(stdout), &v); err != nil {
		t.Fatalf("unparseable JSON: %v, stdout=%s", err, stdout)
	}
	return rc, v, stderr
}
func ruleResult(t *testing.T, raw map[string]any) map[string]any {
	t.Helper()
	v, ok := raw["data"].(map[string]any)
	if !ok {
		t.Fatalf("missing data: %+v", raw)
	}
	return v
}
func TestRoutingRulesCLIWorkflowAndMenuParity(t *testing.T) {
	m := rulesCLIManager(t)
	rc, v, stderr := captureRulesCommand(t, m, "smart-routing-rules", "list")
	if rc != 0 || v["ok"] != true || stderr != "" || ruleResult(t, v)["activation_ready"] != false {
		t.Fatalf("empty: %+v (%d) %s", v, rc, stderr)
	}
	rc, v, stderr = captureRulesCommand(t, m, "smart-routing-rules", "add", "--cidr", "1.1.1.0/24", "--via", "direct")
	if rc != 0 || v["ok"] != true || ruleResult(t, v)["revision"] != float64(1) {
		t.Fatalf("add: %+v (%d) %s", v, rc, stderr)
	}
	rc, v, _ = captureRulesCommand(t, m, "smart-routing-rules", "add", "--domain", "example.org", "--via", "vpn", "--suffix")
	if rc != 0 || ruleResult(t, v)["revision"] != float64(2) {
		t.Fatalf("domain: %+v", v)
	}
	raw := []byte("cidr vpn 9.9.9.9/32\n")
	digest := sha256.Sum256(raw)
	file := filepath.Join(t.TempDir(), "offline.txt")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	rc, v, _ = captureRulesCommand(t, m, "smart-routing-rules", "import", "--file", file, "--source", "test-source", "--sha256", hex.EncodeToString(digest[:]), "--as-of", "2026-10-01")
	if rc != 0 || ruleResult(t, v)["revision"] != float64(3) {
		t.Fatalf("import: %+v", v)
	}
	rc, v, _ = captureRulesCommand(t, m, "smart-routing-rules", "list")
	if rc != 0 || len(ruleResult(t, v)["rules"].([]any)) != 3 || ruleResult(t, v)["general_host_admitted"] != false {
		t.Fatalf("read after import: %+v", v)
	}
	rc, v, _ = captureRulesCommand(t, m, "smart-routing-rules", "remove", "--cidr", "1.1.1.0/24")
	if rc != 0 || ruleResult(t, v)["revision"] != float64(4) {
		t.Fatalf("remove: %+v", v)
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if _, err = writer.Write([]byte("19\n1\n0\n")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	old := os.Stdin
	os.Stdin = input
	code, out, errOut := hostDriftCapturedOutput(t, func() int { return menu(m) })
	os.Stdin = old
	if code != 0 || !strings.Contains(out, "19 Routing Rules") ||
		!strings.Contains(out, "saved_not_applied") || !strings.Contains(out, "9.9.9.9/32") ||
		!strings.Contains(out, "\"activation_ready\": false") {
		t.Fatalf("menu output drift: exit=%d out=%s err=%s", code, out, errOut)
	}
}
func TestRoutingRulesCLIRejectsUntrustedInputBeforeStateWrite(t *testing.T) {
	m := rulesCLIManager(t)
	for _, args := range [][]string{
		{"smart-routing-rules"}, {"smart-routing-rules", "add", "--cidr", "8.8.8.8/32"},
		{"smart-routing-rules", "add", "--cidr", "8.8.8.8/32", "--domain", "example.org", "--via", "vpn"},
		{"smart-routing-rules", "remove", "--cidr", "8.8.8.8/32", "--via", "vpn"},
		{"smart-routing-rules", "list", "--overwrite"},
		{"smart-routing-rules", "preview", "--tunnel-if", "a"},
		{"smart-routing-rules", "unknown-command"},
	} {
		rc, reply, _ := captureRulesCommand(t, m, args...)
		if rc == 0 || reply["ok"] != false {
			t.Fatalf("unsafe arguments accepted: %+v %+v", args, reply)
		}
		if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
			t.Fatalf("bad arguments created state: %+v", args)
		}
	}
	raw := []byte("cidr vpn 8.8.8.8/32\n")
	f := filepath.Join(t.TempDir(), "real-file")
	if err := os.WriteFile(f, raw, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(f, symlink); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "untrusted-fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{symlink, fifo, "https://example.org/secret"} {
		rc, reply, stderr := captureRulesCommand(t, m, "smart-routing-rules", "import", "--file", file,
			"--source", "source", "--as-of", "2026-10-01", "--sha256", strings.Repeat("0", 64))
		if rc == 0 || reply["ok"] != false || strings.Contains(strings.ToLower(stderr+func() string { b, _ := json.Marshal(reply); return string(b) }()), "secret") {
			t.Fatalf("untrusted path accepted or leaked: %q -> %+v", file, reply)
		}
		if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
			t.Fatalf("unsafe input created state: %q", file)
		}
	}
}
