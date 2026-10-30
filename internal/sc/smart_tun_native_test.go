package sc

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func nativeTrialExample(ready bool) smartTUNTrialJournal {
	r := trialV4Example()
	r.IntentType = smartTUNNativeIntent
	r.Native = &smartTUNNativeLedger{Version: 1, NamespaceDev: 1, NamespaceIno: 2, UnderlayIndex: 3, LinkStage: "planned",
		IPv4: nativeTUNPlannedFamily("172.31.99.1/30", nativeTUNTable4), IPv6: nativeTUNPlannedFamily("fd73:99::1/64", nativeTUNTable6),
		NFTName: "scnt_" + r.OperationID, NFT: smartTUNNativeObject{Stage: "planned"}}
	if ready {
		r.CoreStartAttempted = true
		r.Native.StartupVerified = true
		r.Native.LinkIndex = 7
		r.Native.LinkStage = "observed"
		r.Native.LinkSHA256 = strings.Repeat("a", 64)
		r.Native.AddressSHA256 = strings.Repeat("b", 64)
		for _, family := range []int{4, 6} {
			f := nativeFamily(r.Native, family)
			f.DependentSHA256 = strings.Repeat("c", 64)
			f.Rule = smartTUNNativeObject{Stage: "observed", SHA256: strings.Repeat("d", 64)}
			f.Route = f.Rule
			f.Fallback = f.Rule
		}
	}
	return r
}

func nativeNFTFixture(t *testing.T, r smartTUNTrialJournal) ([]map[string]any, nativeTUNNFTObservation) {
	t.Helper()
	raw, err := json.Marshal(nativeNFTObjects(r))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var objects []map[string]any
	if err := decoder.Decode(&objects); err != nil {
		t.Fatal(err)
	}
	for i, object := range objects {
		for _, value := range object {
			value.(map[string]any)["handle"] = json.Number(stringNumber(i + 100))
		}
	}
	observed, err := nativeTUNNFTFromRows(objects, r, 42)
	if err != nil || !observed.Matches {
		t.Fatalf("intended nft graph was not recognized: %v", err)
	}
	return objects, observed
}

func stringNumber(n int) string { raw, _ := json.Marshal(n); return string(raw) }

func bindNativeNFTReceipt(r *smartTUNTrialJournal, observed nativeTUNNFTObservation) {
	r.Native.NFT = smartTUNNativeObject{Stage: "observed", SHA256: observed.SHA256}
	r.Native.NFTHandle = observed.Handle
	r.Native.NFTCount = observed.Count
	r.Native.NFTObjects = observed.Objects
}

func TestSmartTUNNativeJournalStrictSubtypeAndFullValueEquality(t *testing.T) {
	for _, ready := range []bool{false, true} {
		record := nativeTrialExample(ready)
		if ready {
			_, observed := nativeNFTFixture(t, record)
			bindNativeNFTReceipt(&record, observed)
		}
		raw, _ := json.Marshal(record)
		decoded, err := decodeSmartTUNTrial(raw)
		if err != nil || !sameSmartTUNTrial(decoded, record) || decoded.Native == record.Native {
			t.Fatalf("native journal round trip lost full-value equality: %v", err)
		}
		for _, bad := range []string{
			strings.Replace(string(raw), `"startup_verified":`+stringNumberBool(ready), `"startup_verified":null`, 1),
			strings.Replace(string(raw), `"namespace_ino":2`, `"Namespace_ino":2`, 1),
			strings.Replace(string(raw), `"native":{`, `"native":{"unknown":1,`, 1),
			strings.Replace(string(raw), `"native":{`, `"native":{"version":1,`, 1),
			strings.Replace(string(raw), `"intent_type":"`+smartTUNNativeIntent+`"`, `"intent_type":"`+smartTUNTrialIntent+`"`, 1),
		} {
			if _, err := decodeSmartTUNTrial([]byte(bad)); err == nil {
				t.Fatal("ambiguous native subrecord accepted")
			}
		}
	}
	record := nativeTrialExample(false)
	copy := cloneSmartTUNTrial(record)
	copy.Native.NamespaceIno++
	if sameSmartTUNTrial(record, copy) || record.Native.NamespaceIno != 2 {
		t.Fatal("native pointer alias/equality hid identity substitution")
	}
	legacy, _ := json.Marshal(trialV4Example())
	if bytes.Contains(legacy, []byte(`"native"`)) {
		t.Fatal("legacy keyset changed")
	}
	if _, err := decodeSmartTUNTrial(legacy); err != nil {
		t.Fatal(err)
	}
}

func stringNumberBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func TestSmartTUNNativeJournalReloadRetainsSubstitutedEvidence(t *testing.T) {
	m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		expected := nativeTrialExample(false)
		if err := writeSmartTUNTrialLocked(store, expected, nil); err != nil {
			return err
		}
		first, err := reloadSmartTUNTrialLocked(store, expected)
		if err != nil {
			return err
		}
		next := cloneSmartTUNTrial(expected)
		next.Native.LinkStage = "create_possible"
		if err := writeSmartTUNTrialLocked(store, next, &first); err != nil {
			return err
		}
		second, err := reloadSmartTUNTrialLocked(store, next)
		if err != nil || second == first {
			t.Fatalf("legitimate atomic native transition rejected: %v", err)
		}
		foreign := cloneSmartTUNTrial(next)
		foreign.Native.NamespaceIno++
		raw, _ := json.Marshal(foreign)
		path := filepath.Join(m.Dir, "substituted-native-journal")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			return err
		}
		if err := os.Rename(path, filepath.Join(m.Dir, activationJournalFilename)); err != nil {
			return err
		}
		if _, err := reloadSmartTUNTrialLocked(store, next); ErrorCode(err) != "activation_journal_conflict" {
			t.Fatalf("native binding substitution adopted: %v", err)
		}
		retained, _, err := store.readJournal()
		if err != nil || !bytes.Equal(retained, raw) {
			t.Fatal("substitution evidence was changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSmartTUNNativeCoreOwnsNoHostPolicyAndRejectsDialerOverrides(t *testing.T) {
	profile, options := smartTUNFixture()
	raw, err := smartTUNNativeConfig(profile, options)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []struct {
			Address      []string `json:"address"`
			Stack        string   `json:"stack"`
			AutoRoute    bool     `json:"auto_route"`
			AutoRedirect bool     `json:"auto_redirect"`
			DNSMode      string   `json:"dns_mode"`
		} `json:"inbounds"`
		Outbounds []map[string]json.RawMessage `json:"outbounds"`
		Route     map[string]json.RawMessage   `json:"route"`
	}
	if json.Unmarshal(raw, &config) != nil || len(config.Inbounds) != 1 {
		t.Fatal("native config malformed")
	}
	in := config.Inbounds[0]
	if len(in.Address) != 0 || in.Stack != "gvisor" || in.AutoRoute || in.AutoRedirect || in.DNSMode != "disabled" {
		t.Fatal("core retained host cleanup authority")
	}
	for _, outbound := range config.Outbounds {
		mark, ok := nativeTUNNumber(outbound["routing_mark"])
		if !ok || mark != uint64(nativeTUNBypassMark) {
			t.Fatal("native outbound can loop into capture")
		}
	}
	for _, key := range []string{"routing_mark", "bind_interface", "netns", "detour", "domain_resolver", "network_strategy", "connect_timeout"} {
		changed := profile
		changed.Outbound = append(append([]byte{}, profile.Outbound[:len(profile.Outbound)-1]...), []byte(`,"`+key+`":0}`)...)
		if _, err := smartTUNNativeConfig(changed, options); ErrorCode(err) != "trial_unsupported" {
			t.Fatalf("unowned dialer %s accepted: %v", key, err)
		}
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSmartTUNNativeManifestSeparatesOwnershipAndContainment(t *testing.T) {
	record := nativeTrialExample(true)
	objects, observed := nativeNFTFixture(t, record)
	bindNativeNFTReceipt(&record, observed)
	if len(objects) != 24 {
		t.Fatal("compiler graph escaped its fixed dual-stack receipt bound")
	}
	if !nativeTUNNFTReceiptCovers(record, observed, true) || !nativeTUNGuardIntact(record, observed) {
		t.Fatal("complete graph rejected")
	}
	// Actual dropped packets change counters, never ownership or containment.
	last := objects[len(objects)-1]["rule"].(map[string]any)
	last["expr"].([]any)[0].(map[string]any)["counter"] = map[string]any{"packets": json.Number("900"), "bytes": json.Number("80000")}
	changed, err := nativeTUNNFTFromRows(objects, record, 43)
	if err != nil || !nativeTUNNFTReceiptCovers(record, changed, true) {
		t.Fatalf("counter activity became false ownership drift: %v", err)
	}
	captureLost := []map[string]any{}
	for _, object := range objects {
		skip := false
		for kind, value := range object {
			fields := value.(map[string]any)
			skip = (kind == "chain" && fields["name"] == "capture") || (kind == "rule" && fields["chain"] == "capture")
		}
		if !skip {
			captureLost = append(captureLost, object)
		}
	}
	missing, err := nativeTUNNFTFromRows(captureLost, record, 44)
	if err != nil || !nativeTUNNFTReceiptCovers(record, missing, false) || !nativeTUNGuardIntact(record, missing) {
		t.Fatalf("safe capture loss not distinguished: %v", err)
	}
	guardLost, err := nativeTUNNFTFromRows(objects[:len(objects)-1], record, 45)
	if err != nil || !nativeTUNNFTReceiptCovers(record, guardLost, false) || nativeTUNGuardIntact(record, guardLost) {
		t.Fatalf("ownership subset mistaken for guard integrity: %v", err)
	}
	if ErrorCode(nativeTUNRecoveryContainment(record, guardLost)) != "trial_recovery_uncertain" {
		t.Fatal("guard loss permits routing cleanup and Direct leakage")
	}
	// Same semantic rule with a new handle is a replacement, not restoration.
	firstRule := objects[3]["rule"].(map[string]any)
	originalHandle := firstRule["handle"]
	firstRule["handle"] = json.Number("9000")
	replaced, err := nativeTUNNFTFromRows(objects, record, 46)
	if err != nil || nativeTUNNFTReceiptCovers(record, replaced, false) {
		t.Fatal("replacement nft handle adopted")
	}
	firstRule["handle"] = originalHandle
	objects[3], objects[4] = objects[4], objects[3]
	reordered, err := nativeTUNNFTFromRows(objects, record, 47)
	if err == nil && nativeTUNNFTReceiptCovers(record, reordered, false) {
		t.Fatal("rule order changed without conflict")
	}
}

func TestSmartTUNNativePartialEffectsNeverInventOwnership(t *testing.T) {
	for _, stage := range []string{"planned", "effect_possible", "removed"} {
		object := smartTUNNativeObject{Stage: stage}
		if err := nativeTUNObjectRecovery(object, false, ""); err != nil {
			t.Fatal("quiescent absence must be reconcilable")
		}
		err := nativeTUNObjectRecovery(object, true, strings.Repeat("a", 64))
		if err == nil {
			t.Fatalf("%s adopted an unreceipted effect", stage)
		}
		if stage == "effect_possible" && ErrorCode(err) != "trial_recovery_uncertain" {
			t.Fatal("ambiguous post-effect object classified as verified ownership")
		}
	}
	object := smartTUNNativeObject{Stage: "remove_requested", SHA256: strings.Repeat("a", 64)}
	if err := nativeTUNObjectRecovery(object, true, object.SHA256); err != nil {
		t.Fatal(err)
	}
	if ErrorCode(nativeTUNObjectRecovery(object, true, strings.Repeat("b", 64))) != "trial_resource_conflict" {
		t.Fatal("foreign same-slot replacement removable")
	}
}

func TestSmartTUNNativePrePolicyContainmentRequiresFreshAbsence(t *testing.T) {
	for _, stage := range []string{"planned", "effect_possible"} {
		record := nativeTrialExample(true)
		record.Phase = "trial_stop_requested"
		record.Revision = 2
		record.Native.StopReason = "guard"
		record.Native.NFT.Stage = stage
		_, present := nativeNFTFixture(t, record)
		for _, matches := range []bool{false, true} {
			t.Run(stage+"/matches="+stringNumberBool(matches), func(t *testing.T) {
				// The first graph check's absence is not authority for a later
				// reobservation: a present table has no operation-bound receipt,
				// even when its policy happens to match the intended compiler.
				if err := nativeTUNRecoveryContainment(record, nativeTUNNFTObservation{Matches: matches}); err != nil {
					t.Fatalf("fresh pre-policy absence refused: %v", err)
				}
				changed := present
				changed.Matches = matches
				if ErrorCode(nativeTUNRecoveryContainment(record, changed)) != "trial_recovery_uncertain" {
					t.Fatal("new unreceipted graph permitted routing cleanup")
				}
			})
		}
	}
}

func TestSmartTUNNativeRouteSelectorsAndForeignDependencies(t *testing.T) {
	record := nativeTrialExample(true)
	route := `{"dst":"default","dev":"sctunqa0","table":42424,"protocol":247,"scope":"253","prefsrc":"172.31.99.1","metric":100,"flags":[]}`
	rows, _ := selectiveRows(json.RawMessage("[" + route + "]"))
	present, hash, err := nativeTUNResourceRows(rows, record, 4, "route")
	if err != nil || !present || hash == "" {
		t.Fatalf("exact native route rejected: %v", err)
	}
	for _, bad := range []string{strings.Replace(route, `"metric":100`, `"metric":101`, 1), strings.Replace(route, `"scope":"253"`, `"scope":"0"`, 1), strings.Replace(route, `"dev":"sctunqa0"`, `"dev":"foreign0"`, 1), strings.TrimSuffix(route, "}") + `,"nhid":55}`} {
		rows, _ := selectiveRows(json.RawMessage("[" + bad + "]"))
		if _, _, err := nativeTUNResourceRows(rows, record, 4, "route"); err == nil {
			t.Fatal("foreign selector at owned table accepted")
		}
	}
	rows, _ = selectiveRows(json.RawMessage("[" + route + "," + route + "]"))
	if _, _, err := nativeTUNResourceRows(rows, record, 4, "route"); ErrorCode(err) != "trial_resource_conflict" {
		t.Fatal("duplicate native routes accepted")
	}
	var local map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"type":"2","dst":"fd73:99::1","dev":"sctunqa0","table":"255","protocol":"2","metric":0,"flags":[],"pref":"medium"}`), &local)
	if !nativeTUNInitialDependentRoute(record, 6, local) {
		t.Fatal("actual numeric -N local route rejected")
	}
	for _, raw := range []string{`{"nhid":22}`, `{"nexthops":[{"dev":"sctunqa0"}]}`, `{"encap":{}}`} {
		var row map[string]json.RawMessage
		_ = json.Unmarshal([]byte(raw), &row)
		if !nativeTUNIndirectRoute(row) {
			t.Fatal("hidden nexthop dependency ignored")
		}
	}
}

func TestSmartTUNNativeInitialBroadcastIsExactKernelChild(t *testing.T) {
	record := nativeTrialExample(true)
	base := `{"type":"3","dst":"172.31.99.3","dev":"sctunqa0","table":"255","protocol":"2","scope":"253","prefsrc":"172.31.99.1","flags":[]}`
	decode := func(raw string) map[string]json.RawMessage {
		t.Helper()
		var row map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	// fib_add_ifaddr's upper /30 broadcast is independent of NOPREFIXROUTE.
	// Numeric RTN_BROADCAST output must retain the same exact identity.
	for _, raw := range []string{base,
		strings.Replace(base, `"type":"3"`, `"type":3`, 1),
		strings.Replace(strings.Replace(base, `"type":"3"`, `"type":"broadcast"`, 1), `"scope":"253"`, `"scope":"link"`, 1),
		strings.Replace(base, `"dst":"172.31.99.3"`, `"dst":"172.31.99.3/32"`, 1),
		strings.TrimSuffix(base, "}") + `,"metric":0}`,
	} {
		if !nativeTUNInitialDependentRoute(record, 4, decode(raw)) {
			t.Fatalf("exact kernel broadcast child rejected: %s", raw)
		}
	}
	for _, change := range [][2]string{
		{`"172.31.99.3"`, `"172.31.99.0"`}, {`"172.31.99.3"`, `"172.31.99.7"`},
		{`"type":"3"`, `"type":"1"`}, {`"table":"255"`, `"table":"254"`},
		{`"protocol":"2"`, `"protocol":"3"`}, {`"dev":"sctunqa0"`, `"dev":"foreign0"`},
		{`"prefsrc":"172.31.99.1"`, `"prefsrc":"172.31.99.2"`}, {`"prefsrc":"172.31.99.1",`, ""},
		{`"scope":"253"`, `"scope":"0"`}, {`"scope":"253",`, ""}, {`"flags":[]`, `"flags":["onlink"]`},
	} {
		if nativeTUNInitialDependentRoute(record, 4, decode(strings.Replace(base, change[0], change[1], 1))) {
			t.Fatalf("foreign broadcast identity accepted: %v", change)
		}
	}
	for _, extra := range []string{`,"metric":1`, `,"gateway":"172.31.99.2"`, `,"nhid":10`, `,"unknown":true`} {
		if nativeTUNInitialDependentRoute(record, 4, decode(strings.TrimSuffix(base, "}")+extra+"}")) {
			t.Fatal("foreign broadcast attribute was adopted")
		}
	}
	for _, address := range []string{"172.31.99.1/31", "172.31.99.1/32"} {
		changed := cloneSmartTUNTrial(record)
		changed.Native.IPv4.Address = address
		if nativeTUNInitialDependentRoute(changed, 4, decode(base)) {
			t.Fatal("broadcast admitted for a prefix without this kernel child")
		}
	}
	if nativeTUNInitialDependentRoute(record, 6, decode(base)) {
		t.Fatal("IPv4 broadcast admitted as IPv6 dependency")
	}
}

func TestSmartTUNNativeRouteDiagnosticIsBoundedAndCredentialSafe(t *testing.T) {
	var row map[string]json.RawMessage
	if err := json.Unmarshal([]byte(`{"type":"3","dst":"172.31.99.3","dev":"sctunqa0","table":"255","protocol":"2","scope":"253","prefsrc":"172.31.99.1","flags":[]}`), &row); err != nil {
		t.Fatal(err)
	}
	detail := nativeTUNRouteDiagnostic(4, row)
	for _, part := range []string{`"family":4`, `"type":3`, `"dst":"172.31.99.3"`, `"protocol":2`, `"table":255`, `"scope":253`, `"prefsrc":"172.31.99.1"`} {
		if !strings.Contains(detail, part) {
			t.Fatalf("missing bounded route evidence %s: %s", part, detail)
		}
	}
	secret := "vless://never-log-credential@secret.example:443/" + strings.Repeat("x", 5000)
	raw, _ := json.Marshal(secret)
	for _, key := range []string{"type", "dst", "dev", "table", "protocol", "scope", "metric", "prefsrc", "gateway"} {
		row[key] = raw
	}
	row[secret] = json.RawMessage(`{"profile":"never-log-credential"}`)
	row["flags"] = json.RawMessage(`["never-log-credential"]`)
	detail = nativeTUNRouteDiagnostic(6, row)
	if len(detail) > 1024 || strings.Contains(detail, "never-log-credential") || strings.Contains(detail, "secret.example") || strings.Contains(detail, "vless://") || strings.ContainsAny(detail, "\n\r") {
		t.Fatalf("unsafe route diagnostic: length=%d", len(detail))
	}
	if !strings.Contains(detail, `"extra_fields":1`) {
		t.Fatal("unknown-field presence not summarized safely")
	}
}

func TestSmartTUNNativeIPv6RouteUsesKernelUniverseScope(t *testing.T) {
	record := nativeTrialExample(true)
	// IPv6 rt6_fill_node emits RT_SCOPE_UNIVERSE even for our requested
	// device/link route. Numeric iproute2 output omits the default scope.
	base := `{"dst":"default","dev":"sctunqa0","table":"42426","protocol":"247","prefsrc":"fd73:99::1","metric":100,"flags":[],"pref":"medium"}`
	for _, scope := range []string{"", `,"scope":0`, `,"scope":"0"`, `,"scope":"global"`} {
		raw := strings.TrimSuffix(base, "}") + scope + "}"
		rows, err := selectiveRows(json.RawMessage("[" + raw + "]"))
		if err != nil {
			t.Fatal(err)
		}
		present, _, err := nativeTUNResourceRows(rows, record, 6, "route")
		if err != nil || !present {
			t.Fatalf("kernel IPv6 universe scope rejected (%s): %v", scope, err)
		}
	}
	for _, scope := range []string{`253`, `"253"`, `"link"`, `254`, `"host"`, `null`, `""`, `0.0`, `false`} {
		raw := strings.TrimSuffix(base, "}") + `,"scope":` + scope + "}"
		rows, _ := selectiveRows(json.RawMessage("[" + raw + "]"))
		if _, _, err := nativeTUNResourceRows(rows, record, 6, "route"); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("foreign/invalid IPv6 scope %s accepted: %v", scope, err)
		}
	}
	for _, tc := range []struct {
		pref    string
		allowed bool
	}{
		{"", true}, {`"medium"`, true}, {`0`, true}, {`"0"`, true}, {`1`, false}, {`"high"`, false}, {`3`, false}, {`"low"`, false}, {`null`, false}, {`""`, false}, {`0.0`, false},
	} {
		raw := strings.Replace(base, `"pref":"medium"`, `"pref":`+tc.pref, 1)
		if tc.pref == "" {
			raw = strings.Replace(base, `,"pref":"medium"`, "", 1)
		}
		rows, _ := selectiveRows(json.RawMessage("[" + raw + "]"))
		_, _, err := nativeTUNResourceRows(rows, record, 6, "route")
		if (err == nil) != tc.allowed {
			t.Fatalf("route preference %s allowed=%v: %v", tc.pref, tc.allowed, err)
		}
	}
	// Scope differences do not relax the other operation-bound selectors.
	for _, bad := range []string{strings.Replace(base, `"metric":100`, `"metric":101`, 1), strings.Replace(base, `"prefsrc":"fd73:99::1"`, `"prefsrc":"fd73:99::2"`, 1), strings.Replace(base, `"protocol":"247"`, `"protocol":"246"`, 1), strings.Replace(base, `"dev":"sctunqa0"`, `"dev":"foreign0"`, 1)} {
		rows, _ := selectiveRows(json.RawMessage("[" + bad + "]"))
		if _, _, err := nativeTUNResourceRows(rows, record, 6, "route"); err == nil {
			t.Fatal("unrelated IPv6 selector was relaxed")
		}
	}
	// IPv4 must still require link scope; universe is not its equivalent.
	v4 := strings.Replace(strings.Replace(base, `"table":"42426"`, `"table":"42424"`, 1), `"prefsrc":"fd73:99::1"`, `"prefsrc":"172.31.99.1"`, 1)
	rows, _ := selectiveRows(json.RawMessage("[" + v4 + "]"))
	if _, _, err := nativeTUNResourceRows(rows, record, 4, "route"); err == nil {
		t.Fatal("IPv6 scope semantics leaked into IPv4")
	}
	// No family-specific RPDB relaxation: exact numeric protocol/table and
	// masked mark remain mandatory for the IPv6 rule as for IPv4.
	rule := `{"priority":10400,"src":"all","table":"42426","protocol":"247","fwmark":"0x530000","fwmask":"0xff0000"}`
	rows, _ = selectiveRows(json.RawMessage("[" + rule + "]"))
	if present, _, err := nativeTUNResourceRows(rows, record, 6, "rule"); err != nil || !present {
		t.Fatalf("numeric IPv6 rule rejected: %v", err)
	}
	for _, source := range []string{`"fd73:99::/64"`, `null`, `0`, `""`} {
		rows, _ = selectiveRows(json.RawMessage("[" + strings.Replace(rule, `"src":"all"`, `"src":`+source, 1) + "]"))
		if _, _, err := nativeTUNResourceRows(rows, record, 6, "rule"); err == nil {
			t.Fatal("foreign or invalid IPv6 rule source selector accepted")
		}
	}
}

func TestSmartTUNNativeForeignNFTMasksAndIndirectInterfaces(t *testing.T) {
	record := nativeTrialExample(true)
	for _, tc := range []struct {
		raw      string
		conflict bool
	}{
		{`{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16]},"right":16}}`, false},
		{`{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":0}}`, true},
		{`{"mangle":{"key":{"meta":{"key":"mark"}},"value":16}}`, true},
		{`{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":{"set":[3,7]}}}`, true},
		{`{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":"@interfaces"}}`, true},
		{`{"match":{"op":"==","left":7,"right":{"meta":{"key":"oif"}}}}`, true},
		{`{"match":{"op":"==","left":{"meta":{"key":"oif"}},"right":3}}`, false},
	} {
		var value any
		dec := json.NewDecoder(strings.NewReader(tc.raw))
		dec.UseNumber()
		if err := dec.Decode(&value); err != nil {
			t.Fatal(err)
		}
		if got := nativeNFTForeignConflict(value, record); got != tc.conflict {
			t.Fatalf("foreign boundary %s: got %v", tc.raw, got)
		}
	}
}

func TestSmartTUNNativeForeignNFTAllowsOnlyPassiveStatements(t *testing.T) {
	record := nativeTrialExample(true)
	fixture := func(statement string) []map[string]any {
		t.Helper()
		// This complete foreign table is outside the operation's table, and
		// deliberately has a later OUTPUT hook. Its name/address never use
		// a native reserved resource, so overlap-string checks cannot stand
		// in for packet-effect admission.
		raw := `[
		{"table":{"family":"inet","name":"foreign_observer","handle":900}},
		{"chain":{"family":"inet","table":"foreign_observer","name":"observe","handle":901,"type":"filter","hook":"output","prio":100,"policy":"accept"}},
		{"rule":{"family":"inet","table":"foreign_observer","chain":"observe","handle":902,"expr":[` + statement + `]}},
		{"chain":{"family":"inet","table":"foreign_observer","name":"delegate","handle":903}},
		{"counter":{"family":"inet","table":"foreign_observer","name":"observer_packets","handle":905,"packets":8,"bytes":640}},
		{"quota":{"family":"inet","table":"foreign_observer","name":"observer_quota","handle":906,"bytes":1024,"used":10,"inv":false}},
		{"limit":{"family":"inet","table":"foreign_observer","name":"observer_rate","handle":907,"rate":20,"per":"second","burst":4,"unit":"packets","inv":false}},
		{"rule":{"family":"inet","table":"foreign_observer","chain":"delegate","handle":904,"expr":[{"return":null}]}}
		]`
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.UseNumber()
		var objects []map[string]any
		if err := dec.Decode(&objects); err != nil {
			t.Fatal(err)
		}
		return objects
	}
	for _, statement := range []string{
		`{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"198.51.100.20"}}`,
		`{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16]},"right":16}}`,
		`{"counter":{"packets":8,"bytes":640}}`, `{"counter":"observer_packets"}`,
		`{"accept":null}`, `{"drop":null}`, `{"continue":null}`, `{"return":null}`, `{"reject":{"type":"tcp reset"}}`,
		`{"log":{"prefix":"foreign observer","level":"info","flags":["skuid"]}}`,
		`{"limit":{"rate":20,"per":"second","burst":4}}`, `{"limit":"observer_rate"}`,
		`{"quota":{"val":1024,"used":10,"inv":false}}`, `{"quota":"observer_quota"}`,
		`{"jump":{"target":"delegate"}}`, `{"goto":{"target":"delegate"}}`,
	} {
		objects := fixture(statement)
		before, _ := json.Marshal(objects)
		observed, err := nativeTUNNFTFromRows(objects, record, 91)
		if err != nil || observed.Present {
			t.Fatalf("disjoint passive foreign rule refused: %s: %v", statement, err)
		}
		after, _ := json.Marshal(objects)
		if !bytes.Equal(before, after) {
			t.Fatal("foreign admission changed observed evidence")
		}
	}
	for _, statement := range []string{
		`{"dnat":{"family":"ip","addr":"9.9.9.9","port":443}}`,
		`{"snat":{"family":"ip","addr":"198.51.100.1"}}`, `{"masquerade":null}`, `{"redirect":{"port":8080}}`,
		`{"tproxy":{"family":"ip","addr":"127.0.0.1","port":8080}}`,
		`{"mangle":{"key":{"payload":{"protocol":"ip","field":"daddr"}},"value":"9.9.9.9"}}`,
		`{"dup":{"addr":"9.9.9.9","dev":"scqaedge0"}}`, `{"fwd":{"dev":"scqaedge0"}}`,
		`{"queue":{"num":0}}`, `{"notrack":null}`, `{"flow":{"op":"add","flowtable":"foreign_flow"}}`,
		`{"ct helper":"foreign_helper"}`, `{"ct timeout":"foreign_timeout"}`, `{"ct expectation":"foreign_expectation"}`,
		`{"future_packet_rewrite":{"target":"9.9.9.9"}}`,
		`{"accept":{"unknown_effect":true}}`, `{"match":{"op":"future_effect","left":1,"right":1}}`,
		`{"counter":{"packets":0,"bytes":0,"future_effect":1}}`, `{"log":{"unknown_effect":true}}`,
		// Passive form does not bypass the existing ownership dependency gate.
		`{"match":{"op":"==","left":{"&":[{"meta":{"key":"mark"}},16711680]},"right":0}}`,
	} {
		objects := fixture(statement)
		if _, err := nativeTUNNFTFromRows(objects, record, 92); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("unsupported foreign effect escaped admission: %s: %v", statement, err)
		}
	}
	objects := fixture(`{"jump":{"target":"delegate"}}`)
	objects[len(objects)-1]["rule"].(map[string]any)["expr"] = []any{map[string]any{"dnat": map[string]any{"family": "ip", "addr": "9.9.9.9"}}}
	if _, err := nativeTUNNFTFromRows(objects, record, 93); ErrorCode(err) != "trial_resource_conflict" {
		t.Fatal("passive jump hid a rewriting target chain")
	}
	objects = fixture(`{"counter":{"packets":0,"bytes":0}}`)
	objects = append(objects, map[string]any{"flowtable": map[string]any{"family": "inet", "table": "foreign_observer", "name": "foreign_flow", "handle": json.Number("910"), "hook": "ingress", "prio": json.Number("0"), "dev": "scqaedge0"}})
	if _, err := nativeTUNNFTFromRows(objects, record, 94); ErrorCode(err) != "trial_resource_conflict" {
		t.Fatal("foreign offload object escaped admission")
	}
}

func nativeLinkEvent(index int, name string, typ uint16) syscall.NetlinkMessage {
	value := append([]byte(name), 0)
	size := 4 + len(value)
	attribute := make([]byte, (size+3)&^3)
	binary.NativeEndian.PutUint16(attribute[:2], uint16(size))
	binary.NativeEndian.PutUint16(attribute[2:4], syscall.IFLA_IFNAME)
	copy(attribute[4:], value)
	data := make([]byte, syscall.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(data[4:8], uint32(index))
	data = append(data, attribute...)
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: typ}, Data: data}
}

func TestSmartTUNNativeStartupEventsRetainGenerationUncertainty(t *testing.T) {
	record := nativeTrialExample(true)
	if err := nativeTUNLinkEvents([]syscall.NetlinkMessage{nativeLinkEvent(7, "sctunqa0", syscall.RTM_NEWLINK)}, record); err != nil {
		t.Fatal(err)
	}
	for _, event := range []syscall.NetlinkMessage{
		nativeLinkEvent(7, "sctunqa0", syscall.RTM_DELLINK), nativeLinkEvent(7, "renamed0", syscall.RTM_NEWLINK), nativeLinkEvent(8, "sctunqa0", syscall.RTM_NEWLINK),
		{Header: syscall.NlMsghdr{Type: syscall.NLMSG_OVERRUN}}, {Header: syscall.NlMsghdr{Type: syscall.RTM_NEWLINK}, Data: []byte{0}},
	} {
		if err := nativeTUNLinkEvents([]syscall.NetlinkMessage{event}, record); err == nil {
			t.Fatal("lost/replaced attach generation accepted")
		}
	}
	copy := cloneSmartTUNTrial(record)
	copy.Native.StartupVerified = false
	if sameSmartTUNTrial(record, copy) {
		t.Fatal("startup receipt omitted from complete identity")
	}
}
