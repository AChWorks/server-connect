package main

import (
	"bytes"
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

// Exercise every real menu dispatch path, rather than equating a menu
// listing with mutation parity. Each case uses actual stdin and compares
// durable revision + bytes after both positive and rejected operations.
func TestRoutingRulesInteractiveMenuMutationsAndRejections(t *testing.T) {
	m := rulesCLIManager(t)
	path := filepath.Join(m.Dir, "smart-routing-rules.json")
	raw := []byte("cidr vpn 9.9.9.9/32\n")
	updated := []byte("cidr vpn 4.4.4.4/32\n")
	file := filepath.Join(t.TempDir(), "offline-rules.txt")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	sourceDigest := sha256.Sum256(raw)
	replacementDigest := sha256.Sum256(updated)
	sha := hex.EncodeToString(sourceDigest[:])
	newSHA := hex.EncodeToString(replacementDigest[:])

	invoke := func(input string) (string, string) {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(input); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		old := os.Stdin
		os.Stdin = reader
		defer func() { os.Stdin = old; _ = reader.Close() }()
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return menu(m) })
		if code != 0 {
			t.Fatalf("menu terminated unexpectedly: %d %s %s", code, stdout, stderr)
		}
		return stdout, stderr
	}
	report := func() (int, []byte, int) {
		t.Helper()
		state, err := m.InspectSmartRoutingRules()
		if err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return int(state.Revision), contents, len(state.Rules)
	}
	check := func(label, input string, expectedRevision, count int, rejected bool) {
		t.Helper()
		_, before, _ := report()
		_, stderr := invoke("19\n" + input + "0\n")
		rev, after, rules := report()
		if rev != expectedRevision || rules != count {
			t.Fatalf("%s: got revision=%d rules=%d, wanted %d/%d, stderr=%s", label, rev, rules, expectedRevision, count, stderr)
		}
		if rejected {
			if stderr == "" || !bytes.Equal(before, after) {
				t.Fatalf("%s: rejection lost or modified durable rules: %s", label, stderr)
			}
		} else if stderr != "" {
			t.Fatalf("%s: menu failed: %s", label, stderr)
		}
	}
	check("add CIDR", "2\n1.1.1.0/24\ndirect\n", 1, 1, false)
	check("add exact VPN domain", "3\nexample.org\nn\n", 2, 2, false)
	check("add suffix VPN domain", "3\ntest.example.org\ny\n", 3, 3, false)
	check("import", "4\n"+file+"\nmenu-source\n2026-10-01\n"+sha+"\n\n", 4, 4, false)
	check("reject special IPv6", "2\n100::/64\ndirect\n", 4, 4, true)
	check("reject whole ICANN suffix", "3\nco.uk\ny\n", 4, 4, true)
	check("reject whole PRIVATE suffix", "3\ngithub.io\ny\n", 4, 4, true)
	check("reject duplicate", "2\n1.1.1.0/24\ndirect\n", 4, 4, true)
	check("reject wrong import hash", "4\n"+file+"\nbad-source\n2026-10-01\n"+strings.Repeat("0", 64)+"\n\n", 4, 4, true)
	check("reject wrong source CAS", "4\n"+file+"\nmenu-source\n2026-10-02\n"+sha+"\n"+strings.Repeat("0", 64)+"\n", 4, 4, true)
	if err := os.WriteFile(file, updated, 0600); err != nil {
		t.Fatal(err)
	}
	check("replace source", "4\n"+file+"\nmenu-source\n2026-10-02\n"+newSHA+"\n"+sha+"\n", 5, 4, false)
	check("reject stale remove-source CAS", "7\nmenu-source\n"+sha+"\n", 5, 4, true)
	check("remove CIDR", "5\n1.1.1.0/24\n", 6, 3, false)
	check("remove exact domain", "6\nexample.org\nn\n", 7, 2, false)
	check("remove suffix domain", "6\ntest.example.org\ny\n", 8, 1, false)
	check("remove imported source", "7\nmenu-source\n"+newSHA+"\n", 9, 0, false)
	if stdout, stderr := invoke("19\n1\n0\n"); stderr != "" || !strings.Contains(stdout, "saved_not_applied") || !strings.Contains(stdout, "\"activation_ready\": false") {
		t.Fatalf("menu list lost saved-not-applied status: %s %s", stdout, stderr)
	}
}

// Test the CLI argument parser and complete JSON envelope, not only the
// underlying Manager compiler. The fixture is an offline, synthetic profile;
// no sing-box process or kernel route is invoked by this preview.
func TestRoutingRulesCLIPreviewSelectedProfileIsCompileOnly(t *testing.T) {
	m := rulesCLIManager(t)
	for _, rule := range []sc.SmartRoutingRule{
		{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"},
		{Type: "suffix", Value: "test.example.org", Via: "vpn"},
	} {
		if _, err := m.AddSmartRoutingRule(rule); err != nil {
			t.Fatal(err)
		}
	}
	profile, err := sc.ValidateSource([]byte("vless://c2902f3a-1c25-41ef-a8dc-760b483aa247@8.8.8.8:443?type=tcp&security=none#QA"), "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(m.Dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.Dir, "profiles", profile.ID+".json"), encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.Select(profile.ID); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.Dir, "smart-routing-rules.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"smart-routing-rules", "preview", "--tunnel-if", "sctunqa0",
		"--underlay-if", "qaedge0", "--tunnel-ipv4", "172.31.99.1/30",
		"--domestic-cidr", "5.22.0.0/17", "--protected-cidr", "203.0.113.42/32"}
	code, out, stderr := captureRulesCommand(t, m, args...)
	if code != 0 || stderr != "" || out["ok"] != true {
		t.Fatalf("preview failed: %d %+v %s", code, out, stderr)
	}
	report := ruleResult(t, out)
	if report["selected_profile_id"] != profile.ID ||
		report["rules_revision"] != float64(2) ||
		report["rule_count"] != float64(2) ||
		report["validation_level"] != "native_policy_compile_only" ||
		report["core_execution_tested"] != false ||
		report["host_network_inspected"] != false ||
		report["activation_ready"] != false || report["applied"] != false {
		t.Fatalf("CLI preview misrepresented supported scope: %+v", report)
	}
	digest, ok := report["native_config_sha256"].(string)
	if !ok || len(digest) != 64 {
		t.Fatalf("missing compiled hash: %+v", report)
	}
	again, afterPreview, _ := captureRulesCommand(t, m, args...)
	if again != 0 || ruleResult(t, afterPreview)["native_config_sha256"] != digest {
		t.Fatal("CLI preview not deterministic")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("preview modified saved rule bytes")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, "route-activation-journal.json")); !os.IsNotExist(err) {
		t.Fatal("preview created activation state")
	}
}
