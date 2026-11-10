package sc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSmartPreviewUsesSavedProfileAndRulesWithoutActivation(t *testing.T) {
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" {
		t.Skip("NOT_RUN: pinned official sing-box binary was not supplied")
	}
	m := rulesManager(t)
	m.Core = core
	profile, opts := nativePolicyFixture()
	if err := m.withLock(func() error {
		data, err := json.Marshal(profile)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, "profiles", profile.ID+".json"), data); err != nil {
			return err
		}
		return m.save(State{Version: 1, Selected: profile.ID, Desired: "direct", Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	saved, err := m.AddSmartRoutingRule(SmartRoutingRule{Type: "cidr", Value: "1.1.1.0/24", Via: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.PreviewNativeSmartRouting(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CoreConfigAccepted || got.SelectedProfileID != profile.ID ||
		got.RulesRevision != saved.Revision || got.RuleCount != 1 ||
		got.Mode != "bypass_iran" || len(got.NativeConfigSHA256) != 64 ||
		got.ActivationReady || got.Applied || got.GeneralHostAdmitted ||
		got.HostNetworkInspected || got.ValidationLevel != "pinned_official_core_check_only" {
		t.Fatalf("unsafe or incomplete preview result: %+v", got)
	}
	again, err := m.PreviewNativeSmartRouting(opts)
	if err != nil || again.NativeConfigSHA256 != got.NativeConfigSHA256 {
		t.Fatal("preview must be deterministic and must not alter saved state", err)
	}
	if _, err := os.Lstat(filepath.Join(m.Dir, activationJournalFilename)); !os.IsNotExist(err) {
		t.Fatalf("preview created activation journal: %v", err)
	}
	status, err := m.InspectSmartRoutingRules()
	if err != nil || status.ActivationReady || status.GeneralHostAdmitted ||
		status.Revision != saved.Revision {
		t.Fatalf("preview modified saved rules or reported authorization: %+v %v", status, err)
	}
	o := opts
	o.InterfaceName = "lo"
	if _, err := m.PreviewNativeSmartRouting(o); err == nil {
		t.Fatal("invalid native preview accepted")
	}
	o = opts
	o.Mode = "default"
	defaultReport, err := m.PreviewNativeSmartRouting(o)
	if err != nil || defaultReport.NativeConfigSHA256 == got.NativeConfigSHA256 {
		t.Fatalf("default/bypass mode must produce different exact policy digests: %+v %v", defaultReport, err)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "c2902f3a") || strings.Contains(string(raw), "8.8.8.8") {
		t.Fatal("preview report must not serialize selected transport credentials/endpoints")
	}
}
