package sc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBundledIREstimatePreviewCompilesCompletePinnedNativePolicy(t *testing.T) {
	m := rulesManager(t)
	profile, options := smartTUNFixture()
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
	profilePath := filepath.Join(m.Dir, "profiles", profile.ID+".json")
	beforeProfile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	beforeState, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := iranGeoSnapshotFiles.ReadFile("data/iran-dbip-lite-2026-10.json")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := decodeIranGeoSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	options.Exceptions = nil
	options.DomesticCIDRs = nil
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "ipv4", true: "dual-stack"}[ipv6], func(t *testing.T) {
			candidate := options
			if ipv6 {
				candidate.TunnelIPv6 = "fd73:98::1/64"
			}
			preview, err := m.PreviewSmartRoutingRulesBundledEstimatePinned(candidate, "")
			if err != nil {
				t.Fatal(err)
			}
			source := preview.DomesticEstimate
			if source == nil || source.Basis != iranGeoBasis || source.IPv4Count != 2024 ||
				source.IPv6Count != 1014 || source.PrefixSHA256 != iranGeoPrefixSHA256 ||
				source.SourceSHA256 != iranGeoArchiveSHA256 || source.AsOf != "2026-10-01" ||
				!source.FormatAndChecksumVerified || source.PublisherSignatureVerified ||
				source.SafeForGeographicRouting || source.ActivationReady ||
				preview.ActivationReady || preview.Applied || preview.HostNetworkInspected ||
				preview.CoreExecutionTested || preview.ValidationLevel != "native_policy_compile_only" ||
				preview.RulesRevision != 0 || preview.RuleCount != 0 ||
				preview.SelectedProfileID != profile.ID {
				t.Fatalf("estimate was promoted to authority or metadata lost: %+v", preview)
			}
			expectedOptions := candidate
			expectedOptions.DomesticCIDRs = append([]string(nil), snapshot.IPv4...)
			if ipv6 {
				expectedOptions.DomesticIPv6CIDRs = append([]string(nil), snapshot.IPv6...)
			}
			config, err := smartTUNNativeConfig(profile, expectedOptions)
			if err != nil {
				t.Fatal(err)
			}
			checksum := sha256.Sum256(config)
			if preview.NativeConfigSHA256 != hex.EncodeToString(checksum[:]) {
				t.Fatal("preview did not compile the exact complete pinned dataset")
			}
			// CI provides the pinned real sing-box 1.14.3 executable; run
			// its actual parser against all 2,024 prefixes, not only our
			// own JSON compiler. No TUN creation or host Apply occurs.
			if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
				if err := CheckConfig(core, t.TempDir(), config); err != nil {
					t.Fatalf("real pinned sing-box rejected full bundled IPv4 native preview: %v", err)
				}
			}
			repeated, err := m.PreviewSmartRoutingRulesBundledEstimatePinned(candidate, "")
			if err != nil || !reflect.DeepEqual(preview, repeated) {
				t.Fatalf("same input was not deterministic: %+v %+v %v", preview, repeated, err)
			}
		})
	}
	afterProfile, err := os.ReadFile(profilePath)
	if err != nil || string(afterProfile) != string(beforeProfile) {
		t.Fatal("compile-only preview changed the private selected profile")
	}
	afterState, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil || string(afterState) != string(beforeState) {
		t.Fatal("compile-only preview changed current mode or selection")
	}
	if _, err := os.Stat(filepath.Join(m.Dir, smartRoutingRulesFilename)); !os.IsNotExist(err) {
		t.Fatal("compile-only estimate was unexpectedly saved as operator rules")
	}

	// An operator-saved VPN exception inside the estimated Iranian space must
	// remain higher priority than the broad estimated Direct rule. The
	// independently compiled native configuration binds both to its digest.
	override := SmartRoutingRule{Type: "cidr", Value: "5.22.0.10/32", Via: "vpn"}
	if _, err := m.AddSmartRoutingRule(override); err != nil {
		t.Fatal(err)
	}
	candidate := options
	got, err := m.PreviewSmartRoutingRulesBundledEstimatePinned(candidate, "")
	if err != nil || got.RuleCount != 1 || got.RulesRevision != 1 ||
		got.DomesticEstimate == nil || got.ActivationReady || got.Applied {
		t.Fatalf("saved override was not retained or preview claimed admission: %+v %v", got, err)
	}
	candidate.DomesticCIDRs = append([]string(nil), snapshot.IPv4...)
	candidate.Exceptions = []SmartTUNCIDRException{{CIDR: override.Value, Via: override.Via}}
	expectedConfig, err := smartTUNNativeConfig(profile, candidate)
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(expectedConfig)
	if got.NativeConfigSHA256 != hex.EncodeToString(expectedDigest[:]) {
		t.Fatal("saved explicit VPN override was not compiled ahead of the estimated country rule")
	}
}

func TestBundledIREstimatePreviewFailsClosedOnMixedOrUnsafeInput(t *testing.T) {
	m := rulesManager(t)
	_, opts := smartTUNFixture()
	opts.Exceptions = nil
	opts.DomesticCIDRs = nil
	cases := []struct {
		name     string
		change   func(*SmartTUNCandidateOptions)
		wantCode string
	}{
		{"mixed-ipv4", func(x *SmartTUNCandidateOptions) { x.DomesticCIDRs = []string{"5.22.0.0/17"} }, "invalid_arguments"},
		{"mixed-ipv6", func(x *SmartTUNCandidateOptions) { x.DomesticIPv6CIDRs = []string{"2a01:1::/32"} }, "invalid_arguments"},
		{"caller-exception", func(x *SmartTUNCandidateOptions) {
			x.Exceptions = []SmartTUNCIDRException{{CIDR: "9.9.9.9/32", Via: "direct"}}
		}, "invalid_arguments"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			invalid := opts
			tc.change(&invalid)
			if _, err := m.PreviewSmartRoutingRulesBundledEstimatePinned(invalid, ""); ErrorCode(err) != tc.wantCode {
				t.Fatalf("unsafe input accepted or wrong error: %v", err)
			}
		})
	}
}
