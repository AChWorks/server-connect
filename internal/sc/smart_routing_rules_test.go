package sc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func rulesManager(t *testing.T) *Manager {
	t.Helper()
	return New(filepath.Join(t.TempDir(), "private"), "", 0)
}
func TestRoutingRulesDurableLifecycle(t *testing.T) {
	m := rulesManager(t)
	s, err := m.InspectSmartRoutingRules()
	if err != nil || s.Present || s.Revision != 0 || s.ActivationReady {
		t.Fatalf("initial: %+v %v", s, err)
	}
	s, err = m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"})
	if err != nil || s.Revision != 1 {
		t.Fatalf("add: %+v %v", s, err)
	}
	s, err = m.AddSmartRoutingRule(SmartRoutingRule{Type: "domain", Value: "example.org", Via: "vpn"})
	if err != nil || s.Revision != 2 {
		t.Fatalf("domain: %+v %v", s, err)
	}
	raw := []byte("# offline operator list\ncidr vpn 9.9.9.9/32\nsuffix vpn test.example.org\n")
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	s, err = m.ImportSmartRoutingRules("offline", "2026-10-01", digest, "", raw)
	if err != nil || s.Revision != 3 || len(s.Rules) != 4 || len(s.Imports) != 1 || s.ActivationReady || s.Imports[0].PublisherSignatureVerified {
		t.Fatalf("import: %+v %v", s, err)
	}
	second, err := m.InspectSmartRoutingRules()
	if err != nil || !reflect.DeepEqual(s, second) {
		t.Fatalf("persist: %+v %+v %v", s, second, err)
	}
	s, err = m.ImportSmartRoutingRules("offline", "2026-10-01", digest, "", raw)
	if err != nil || s.Revision != 3 {
		t.Fatalf("idempotency: %+v %v", s, err)
	}
	replacement := []byte("cidr vpn 8.8.8.8/32\n")
	newHash := sha256.Sum256(replacement)
	newDigest := hex.EncodeToString(newHash[:])
	if _, err = m.ImportSmartRoutingRules("offline", "2026-10-05", newDigest, "", replacement); ErrorCode(err) != "routing_rules_conflict" {
		t.Fatalf("overwrite not refused: %v", err)
	}
	s, err = m.ImportSmartRoutingRules("offline", "2026-10-05", newDigest, digest, replacement)
	if err != nil || s.Revision != 4 || len(s.Rules) != 3 {
		t.Fatalf("replace: %+v %v", s, err)
	}
	s, err = m.RemoveSmartRoutingRule("cidr", "1.1.1.0/24")
	if err != nil || s.Revision != 5 || len(s.Rules) != 2 {
		t.Fatalf("remove: %+v %v", s, err)
	}
	s, err = m.RemoveSmartRoutingSource("offline", newDigest)
	if err != nil || s.Revision != 6 || len(s.Rules) != 1 || len(s.Imports) != 0 {
		t.Fatalf("remove import: %+v %v", s, err)
	}
}
func TestRoutingRulesRejectUnsafeAndConflicting(t *testing.T) {
	m := rulesManager(t)
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"}); err != nil {
		t.Fatal(err)
	}
	tests := []SmartRoutingRule{
		{Type: "cidr", Value: "0.0.0.0/0", Via: "direct"},
		{Type: "cidr", Value: "1.0.0.0/8", Via: "direct"},
		{Type: "cidr", Value: "10.0.0.0/8", Via: "vpn"},
		{Type: "cidr", Value: "192.0.2.0/24", Via: "vpn"},
		{Type: "cidr", Value: "1.1.1.1/24", Via: "vpn"},
		{Type: "cidr", Value: "1.1.1.1/32", Via: "vpn"},
		{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"},
		{Type: "domain", Value: "example.org", Via: "direct"},
		{Type: "domain", Value: "https://example.org/private", Via: "vpn"},
		{Type: "suffix", Value: "*.example.org", Via: "vpn"},
		{Type: "domain", Value: "singlelabel", Via: "vpn"},
		{Type: "invalid", Value: "8.8.8.8/32", Via: "vpn"},
		{Type: "cidr", Value: "8.8.8.8/32", Via: "auto"},
		{Type: "cidr", Value: "2001:4860::/32", Via: "direct"},
	}
	for _, x := range tests {
		if _, err := m.AddSmartRoutingRule(x); err == nil {
			t.Fatalf("unsafe accepted: %+v", x)
		}
	}
	s, err := m.InspectSmartRoutingRules()
	if err != nil || s.Revision != 1 || len(s.Rules) != 1 {
		t.Fatalf("refused mutation occurred: %+v %v", s, err)
	}
}
func TestRoutingRulesImportFailClosed(t *testing.T) {
	m := rulesManager(t)
	for _, raw := range []string{"cidr direct 0.0.0.0/0\n", "domain direct example.org\n", "cidr vpn 8.8.8.8/32 EXTRA\n", "cidr vpn 8.8.8.8/32\ncidr direct 8.8.8.8/32\n", "cidr vpn 127.0.0.1/32\n", "cidr vpn 8.8.8.8/32\r\n", "# no rules\n"} {
		h := sha256.Sum256([]byte(raw))
		if _, err := m.ImportSmartRoutingRules("list", "2026-10-01", hex.EncodeToString(h[:]), "", []byte(raw)); err == nil {
			t.Fatalf("invalid import accepted: %q", raw)
		}
	}
	raw := []byte("cidr vpn 8.8.8.8/32\n")
	if _, err := m.ImportSmartRoutingRules("list", "2026-10-01", strings.Repeat("0", 64), "", raw); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	s, err := m.InspectSmartRoutingRules()
	if err != nil || s.Present {
		t.Fatalf("failed import wrote state: %+v %v", s, err)
	}
}
func TestRoutingRulesStateConflictsAndCorruption(t *testing.T) {
	m := rulesManager(t)
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "8.8.8.8/32", Via: "vpn"}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(m.Dir, smartRoutingRulesFilename)
	if err := os.WriteFile(filepath.Join(m.Dir, activationJournalFilename), []byte("{\"version\":4}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"}); ErrorCode(err) != "guard_pending" {
		t.Fatalf("journal mutation not blocked: %v", err)
	}
	if err := os.Remove(filepath.Join(m.Dir, activationJournalFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", f); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InspectSmartRoutingRules(); err == nil {
		t.Fatal("symlink followed")
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "9.9.9.9/32", Via: "vpn"}); err == nil {
		t.Fatal("symlink overwritten")
	}
	if err := os.Remove(f); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		"{\"version\":1,\"version\":1,\"revision\":1,\"manual\":[],\"imports\":[]}",
		"{\"version\":1,\"revision\":1,\"manual\":[{\"type\":\"CIDR\",\"value\":\"8.8.8.8/32\",\"via\":\"vpn\"}],\"imports\":[]}",
		"{\"version\":2,\"revision\":1,\"manual\":[],\"imports\":[]}",
		"{\"version\":1,\"revision\":1,\"manual\":[],\"imports\":[],\"unknown\":true}",
	} {
		if err := os.WriteFile(f, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.InspectSmartRoutingRules(); err == nil {
			t.Fatalf("untrusted state accepted: %s", raw)
		}
	}
}
func TestRoutingRulesConcurrencyAndStale(t *testing.T) {
	m := rulesManager(t)
	rows := []string{"8.8.8.8/32", "8.8.4.4/32", "9.9.9.9/32", "1.1.1.1/32", "4.4.4.4/32", "5.5.5.5/32", "6.6.6.6/32", "7.7.7.7/32"}
	var wg sync.WaitGroup
	errs := make(chan error, len(rows))
	for _, r := range rows {
		wg.Add(1)
		go func(v string) {
			defer wg.Done()
			_, e := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: v, Via: "vpn"})
			errs <- e
		}(r)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	s, e := m.InspectSmartRoutingRules()
	if e != nil || s.Revision != 8 || len(s.Rules) != 8 {
		t.Fatalf("lost writes: %+v %v", s, e)
	}
	raw := []byte("cidr vpn 11.11.11.0/24\n")
	h := sha256.Sum256(raw)
	s, e = m.ImportSmartRoutingRules("old", "2020-01-01", hex.EncodeToString(h[:]), "", raw)
	if e != nil || len(s.Imports) != 1 || !s.Imports[0].StaleOver30Days || s.Imports[0].PublisherSignatureVerified || s.ActivationReady {
		t.Fatalf("stale/trust: %+v %v", s, e)
	}
	if _, err := validateSmartRoutingAsOf("2099-01-01", time.Now()); err == nil {
		t.Fatal("future accepted")
	}
}

func TestRoutingRulesRejectBroadAggregateAndNullSchema(t *testing.T) {
	m := rulesManager(t)
	var rows []string
	for i := 0; i < 65; i++ {
		rows = append(rows, fmt.Sprintf("cidr direct 11.0.%d.0/24", i))
	}
	raw := []byte(strings.Join(rows, "\n") + "\n")
	h := sha256.Sum256(raw)
	if _, err := m.ImportSmartRoutingRules("operator", "2026-10-01", hex.EncodeToString(h[:]), "", raw); err == nil {
		t.Fatal("aggregate Direct breadth greater than native compiler limit accepted")
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "suffix", Value: "com", Via: "vpn"}); err == nil {
		t.Fatal("unscoped whole-TLD suffix accepted")
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record := []byte("{\"version\":1,\"revision\":1,\"manual\":null,\"imports\":[]}\n")
		return store.writeSmartTUNFile(smartRoutingRulesFilename, record, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.InspectSmartRoutingRules(); err == nil {
		t.Fatal("null instead of a saved rules array accepted")
	}
}

func TestRoutingRulesNativeCompilerPreviewNoNetworkEffects(t *testing.T) {
	m := rulesManager(t)
	if _, err := m.PreviewSmartRoutingRules(SmartTUNCandidateOptions{}); err == nil {
		t.Fatal("preview without a selected profile accepted")
	}
	profile, original := smartTUNFixture()
	profile.ID = "0123456789abcdef"
	if err := m.withLock(func() error {
		state := State{Version: 1, Desired: "direct", Port: m.Port, Selected: profile.ID}
		if err := m.save(state); err != nil {
			return err
		}
		raw, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		return put(filepath.Join(m.Dir, "profiles", profile.ID+".json"), raw)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "suffix", Value: "example.org", Via: "vpn"}); err != nil {
		t.Fatal(err)
	}
	opts := original
	opts.Exceptions = nil
	p, err := m.PreviewSmartRoutingRules(opts)
	if err != nil || p.RulesRevision != 2 || p.SelectedProfileID != profile.ID || p.RuleCount != 2 ||
		len(p.NativeConfigSHA256) != 64 || p.ValidationLevel != "native_policy_compile_only" ||
		p.CoreExecutionTested || p.HostNetworkInspected || p.ActivationReady || p.Applied {
		t.Fatalf("preview must compile only, no activation: %+v %v", p, err)
	}
	again, err := m.PreviewSmartRoutingRules(opts)
	if err != nil || !reflect.DeepEqual(p, again) {
		t.Fatalf("compiled plan unstable: %+v %+v %v", p, again, err)
	}
	opts.Exceptions = []SmartTUNCIDRException{{CIDR: "8.8.8.8/32", Via: "direct"}}
	if _, err := m.PreviewSmartRoutingRules(opts); err == nil {
		t.Fatal("caller-supplied exceptions bypassed saved rules")
	}
}
