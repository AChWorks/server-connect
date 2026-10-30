package sc

import (
	"encoding/json"
	"strings"
	"syscall"
	"testing"
)

// These exact original Version1 evidence objects are independent of the new
// marshaler. Only the existing native ledger fixture supplies ownership fields.
const legacyHealthyEvidenceJSON = `{"underlay_healthy":true,"vpn_healthy":true,"ipv4_tcp":true,"ipv4_udp":true,"ipv4_dns":true,"ipv6_tcp":true,"ipv6_udp":true,"ipv6_dns":true,"failed_targets":0,"probe_count":13,"elapsed_ms":20,"reason":"healthy"}`
const legacyUnmeasuredEvidenceJSON = `{"underlay_healthy":false,"vpn_healthy":false,"ipv4_tcp":false,"ipv4_udp":false,"ipv4_dns":false,"ipv6_tcp":false,"ipv6_udp":false,"ipv6_dns":false,"failed_targets":0,"probe_count":0,"elapsed_ms":0,"reason":""}`

func supervisionWire(t *testing.T, r smartTUNTrialJournal, change func(map[string]json.RawMessage)) []byte {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var top, supervised map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || json.Unmarshal(top["supervised"], &supervised) != nil {
		t.Fatal("fixture JSON could not be decoded")
	}
	change(supervised)
	top["supervised"], err = json.Marshal(supervised)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(top)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func legacySupervisedExample(t *testing.T, confirmed bool) smartTUNTrialJournal {
	t.Helper()
	raw := supervisionWire(t, supervisedExample(t, confirmed), func(s map[string]json.RawMessage) {
		s["version"] = json.RawMessage("1")
		evidence := legacyUnmeasuredEvidenceJSON
		if confirmed {
			evidence = legacyHealthyEvidenceJSON
		}
		s["evidence"] = json.RawMessage(evidence)
	})
	r, err := decodeSmartTUNTrial(raw)
	if err != nil {
		t.Fatalf("original Version1 read failed: %v", err)
	}
	return r
}

func assertLegacySupervisionShape(t *testing.T, raw []byte) {
	t.Helper()
	var top, supervised, evidence map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || json.Unmarshal(top["supervised"], &supervised) != nil ||
		json.Unmarshal(supervised["evidence"], &evidence) != nil || string(supervised["version"]) != "1" || len(evidence) != 12 {
		t.Fatalf("legacy write changed evidence version/shape: %s", raw)
	}
	for _, key := range strings.Fields("underlay_healthy vpn_healthy ipv4_tcp ipv4_udp ipv4_dns ipv6_tcp ipv6_udp ipv6_dns failed_targets probe_count elapsed_ms reason") {
		if _, ok := evidence[key]; !ok {
			t.Fatalf("legacy evidence lost %s", key)
		}
	}
	if _, err := decodeSmartTUNTrial(raw); err != nil {
		t.Fatalf("legacy durable write cannot be reread: %v", err)
	}
}

func TestSupervisedLegacyRecoveryPreservesExactReadStopCleanupWriteShape(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		dir := privateJournalTempDir(t)
		manager := New(dir, DefaultCore, DefaultPort)
		r := legacySupervisedExample(t, confirmed)
		original := cloneSmartTUNTrial(r)
		if err := manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			if err := writeSmartTUNTrialLocked(store, r, nil); err != nil {
				return err
			}
			if err := supervisedRequestStop(store, &r, "legacy_reapply_required"); err != nil {
				return err
			}
			raw, _, err := store.readJournal()
			if err != nil {
				return err
			}
			assertLegacySupervisionShape(t, raw)
			if r.Supervised.Version != 1 || r.Supervised.Evidence != original.Supervised.Evidence ||
				r.Supervised.HeartbeatMS != original.Supervised.HeartbeatMS || r.Supervised.LeaseDeadlineMS != original.Supervised.LeaseDeadlineMS {
				t.Fatal("legacy stop migrated health evidence or renewed authority")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// Reopen after an interrupted durable stop. This exercises only journal
		// state transitions; genuine native removal is covered by installed QA.
		if err := manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			found, _, err := loadSmartTUNTrialLocked(store)
			if err != nil || !sameSmartTUNTrial(r, found) || found.Phase != "trial_stop_requested" {
				t.Fatalf("interrupted legacy stop lost exact ownership: %v", err)
			}
			next := cloneSmartTUNTrial(found)
			next.Native.LinkStage, next.Native.NFT.Stage = "removed", "removed"
			for _, family := range []int{4, 6} {
				if nativeFamily(next.Native, family).Address != "" {
					for _, kind := range []string{"route", "rule", "fallback"} {
						nativeTUNResource(next.Native, family, kind).Stage = "removed"
					}
				}
			}
			next.Phase, next.Revision = "trial_recovered", 2
			next.Supervised.Generation++
			if err := nativeTUNAdvance(store, &r, next); err != nil {
				return err
			}
			next = cloneSmartTUNTrial(r)
			next.Phase, next.Revision = "trial_cleanup_pending", 4
			identity, err := reloadSmartTUNTrialLocked(store, r)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(next)
			if err != nil {
				return err
			}
			// A failure after rename leaves a visible cleanup record. Its exact
			// Version1 encoding must survive both a later read and sync retry.
			err = store.writeJournalWithDirSync(append(raw, '\n'), &identity, func(int) error { return syscall.EIO })
			if ErrorCode(err) != "activation_journal_unavailable" {
				t.Fatalf("cleanup durability fault not injected: %v", err)
			}
			r = next
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			found, identity, err := loadSmartTUNTrialLocked(store)
			if err != nil || !sameSmartTUNTrial(r, found) {
				t.Fatalf("interrupted cleanup lost old record: %v", err)
			}
			if err := syncSmartTUNCleanupLocked(store, identity, found, syscall.Fsync); err != nil {
				return err
			}
			raw, _, err := store.readJournal()
			if err == nil {
				assertLegacySupervisionShape(t, raw)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSupervisedLegacyCannotConfirmProbeRenewOrReconnect(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		r := legacySupervisedExample(t, confirmed)
		if smartTUNConfirmMatches(r, r.OperationID, r.Revision, strings.Repeat("b", 64), r.BootID, 100050) {
			t.Fatal("old confirmation authorized HTTPS operation")
		}
		// The early legacy decision does not inspect services, native state or
		// a clock; a nil store is safe and no second probe engine is involved.
		if reason := inspectSupervisedRuntime(nil, r, true); reason != "legacy_reapply_required" {
			t.Fatalf("legacy runtime admitted inspection/probe path: %s", reason)
		}
		if reason := supervisedRuntimeReason(r, smartTUNTrialUnitObservation{}, false, "other-boot", 0); reason != "legacy_reapply_required" {
			t.Fatalf("legacy refusal was deferred behind unrelated observation: %s", reason)
		}
		next, stop, reconnect := advanceSupervisedHealth(r, healthySupervisedEvidence(), 110000)
		if !sameSmartTUNTrial(r, next) || stop != "legacy_reapply_required" || reconnect {
			t.Fatal("new HTTPS health migrated or renewed old operation")
		}
		if budget, reason := supervisedReconnectBudget(r, 110000); budget != 0 || reason != "legacy_reapply_required" {
			t.Fatal("old operation received reconnect authority")
		}
		if smartTUNSupervisedStatusLabel(r) != "supervised_reapply_required" {
			t.Fatal("legacy status advertised current healthy supervision")
		}
		receipt := smartTUNReceipt(r, false, false)
		if receipt.HealthEvidenceVersion != 1 || receipt.SupervisionState != "reapply_required" || receipt.HealthReason != "legacy_reapply_required" ||
			receipt.HealthEvidence == nil || receipt.HealthEvidence.IPv4HTTPS || receipt.HealthEvidence.IPv6HTTPS {
			t.Fatalf("legacy receipt acquired HTTPS proof: %+v", receipt)
		}
		for _, result := range receipt.HealthEvidence.HTTPSResults {
			if result != (SmartTUNHTTPSResult{Result: "not_run"}) {
				t.Fatal("legacy receipt claimed an HTTPS execution")
			}
		}
		r.Phase, r.Revision = "trial_cleared", 5
		r.Supervised.State, r.Supervised.Reason = "stopped", "legacy_reapply_required"
		final := smartTUNRecoveryReceipt(smartTUNReceipt(r, false, true))
		if final.HealthEvidenceVersion != 1 || final.HealthReason != "legacy_reapply_required" || final.HealthEvidence == nil || !final.RecoveryVerified {
			t.Fatal("independent final output lost legacy evidence basis")
		}
	}
}

func TestSupervisedEvidenceVersionsRejectMixedNullAliasedOrUnknownShapes(t *testing.T) {
	current := supervisedExample(t, true)
	legacy := legacySupervisedExample(t, true)
	for _, tc := range []struct {
		name   string
		record smartTUNTrialJournal
		change func(map[string]json.RawMessage)
	}{
		{"v2-evidence-in-v1", current, func(s map[string]json.RawMessage) { s["version"] = json.RawMessage("1") }},
		{"v1-evidence-in-v2", legacy, func(s map[string]json.RawMessage) { s["version"] = json.RawMessage("2") }},
		{"future-version", current, func(s map[string]json.RawMessage) { s["version"] = json.RawMessage("3") }},
		{"null-version", current, func(s map[string]json.RawMessage) { s["version"] = json.RawMessage("null") }},
		{"string-version", current, func(s map[string]json.RawMessage) { s["version"] = json.RawMessage(`"2"`) }},
		{"null-evidence", current, func(s map[string]json.RawMessage) { s["evidence"] = json.RawMessage("null") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeSmartTUNTrial(supervisionWire(t, tc.record, tc.change)); err == nil {
				t.Fatal("mixed, future or null evidence accepted")
			}
		})
	}
	raw, _ := json.Marshal(current)
	for _, tc := range []struct{ old, new string }{
		{`"ipv4_https":true`, `"ipv4_https":null`},
		{`"ipv4_https":true`, `"IPv4_HTTPS":true`},
		{`"ipv4_https":true`, `"ipv4_https":true,"ipv4_https":false`},
		{`"https_results":[`, `"HTTPS_RESULTS":[`},
		{`"result":"pass"`, `"result":null`},
		{`"result":"pass"`, `"Result":"pass"`},
		{`"result":"pass"`, `"result":"pass","result":"pass"`},
		{`"result":"pass"`, `"result":"peer-supplied-private-error"`},
		{`"status_code":200`, `"status_code":null`},
		{`"status_code":200`, `"Status_Code":200`},
		{`"status_code":200`, `"status_code":"200"`},
		{`"status_code":200`, `"status_code":200.5`},
		{`"status_code":200`, `"status_code":200,"status_code":200`},
		{`"status_code":200`, `"status_code":200,"extra":0`},
	} {
		bad := strings.Replace(string(raw), tc.old, tc.new, 1)
		if bad == string(raw) {
			t.Fatalf("negative mutation did not affect fixture: %s", tc.old)
		}
		if _, err := decodeSmartTUNTrial([]byte(bad)); err == nil {
			t.Fatalf("ambiguous nested HTTPS evidence accepted: %s", tc.new)
		}
	}
	for _, results := range []string{"null", "{}", "[]", `[null,null,null,null]`,
		`[{"result":"pass","status_code":200}]`,
		`[{"result":"pass","status_code":200},{"result":"pass","status_code":200},{"result":"pass","status_code":200},{"result":"pass","status_code":200},{"result":"pass","status_code":200}]`} {
		bad := supervisionWire(t, current, func(s map[string]json.RawMessage) {
			var evidence map[string]json.RawMessage
			_ = json.Unmarshal(s["evidence"], &evidence)
			evidence["https_results"] = json.RawMessage(results)
			s["evidence"], _ = json.Marshal(evidence)
		})
		if _, err := decodeSmartTUNTrial(bad); err == nil {
			t.Fatalf("invalid fixed target array accepted: %s", results)
		}
	}
}

func TestSupervisedV2SemanticEvidenceAndValueCopy(t *testing.T) {
	r := supervisedExample(t, true)
	for _, mutate := range []func(*SmartTUNHealthEvidence){
		func(e *SmartTUNHealthEvidence) { e.IPv4HTTPS = false },
		func(e *SmartTUNHealthEvidence) { e.IPv6HTTPS = false },
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0].StatusCode = 0 },
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0].StatusCode = 503 },
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0].Result = "http_status" },
		func(e *SmartTUNHealthEvidence) {
			e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "tls_identity_failed", StatusCode: 200}
		},
		func(e *SmartTUNHealthEvidence) {
			e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "path_mismatch", StatusCode: 200}
		},
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "not_run"} },
		func(e *SmartTUNHealthEvidence) { e.ProbeCount = 13 },
		func(e *SmartTUNHealthEvidence) { e.Reason = "vpn_ipv4_https_failed" },
	} {
		next := cloneSmartTUNTrial(r)
		mutate(&next.Supervised.Evidence)
		if sameSmartTUNTrial(r, next) || r.Supervised.Evidence != healthySupervisedEvidence() {
			t.Fatal("HTTPS value change was hidden or aliased into the snapshot")
		}
		if validateSmartTUNTrial(next) == nil {
			t.Fatal("unsupported HTTPS status/family/version claim accepted")
		}
	}
	// Equality must include a semantically valid partial HTTP status as well.
	next := cloneSmartTUNTrial(r)
	next.Supervised.Evidence.HTTPSResults[0] = SmartTUNHTTPSResult{"http_status", 503}
	next.Supervised.Evidence.FailedTargets = 1
	next.Supervised.Evidence.Reason = "healthy_partial_targets"
	if validateSmartTUNTrial(next) != nil || sameSmartTUNTrial(r, next) {
		t.Fatal("valid partial result was rejected or escaped full-value equality")
	}
	old := legacySupervisedExample(t, true)
	old.Supervised.Evidence.IPv4HTTPS = true
	if validateSmartTUNTrial(old) == nil {
		t.Fatal("Version1 in-memory record acquired HTTPS proof")
	}
	if _, err := json.Marshal(old); err == nil {
		t.Fatal("Version1 serialization silently discarded mixed HTTPS evidence")
	}
}

func TestSupervisedDisabledHTTPSFamilyAndUnmeasuredSlotsCannotClaimExecution(t *testing.T) {
	evidence := healthySupervisedEvidence()
	evidence.IPv6TCP, evidence.IPv6UDP, evidence.IPv6DNS, evidence.IPv6HTTPS = false, false, false, false
	evidence.ProbeCount = 9
	evidence.HTTPSResults[2], evidence.HTTPSResults[3] = SmartTUNHTTPSResult{Result: "not_run"}, SmartTUNHTTPSResult{Result: "not_run"}
	if !validSmartTUNHTTPSEvidence(evidence, false) {
		t.Fatal("valid IPv4-only HTTPS evidence rejected")
	}
	for _, mutate := range []func(*SmartTUNHealthEvidence){
		func(e *SmartTUNHealthEvidence) { e.IPv6HTTPS = true },
		func(e *SmartTUNHealthEvidence) {
			e.HTTPSResults[2] = SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
		},
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[3].StatusCode = 200 },
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "not_run"} },
	} {
		next := evidence
		mutate(&next)
		if validSmartTUNHTTPSEvidence(next, false) {
			t.Fatal("disabled or unexecuted target supplied HTTPS proof")
		}
	}
	canceled := smartTUNHealthNotRunEvidence()
	canceled.Reason = "round_canceled"
	if !validSmartTUNHTTPSEvidence(canceled, true) {
		t.Fatal("unstarted canceled round rejected")
	}
	for _, mutate := range []func(*SmartTUNHealthEvidence){
		func(e *SmartTUNHealthEvidence) { e.UnderlayHealthy = true },
		func(e *SmartTUNHealthEvidence) { e.IPv4TCP = true },
		func(e *SmartTUNHealthEvidence) {
			e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
		},
		func(e *SmartTUNHealthEvidence) { e.HTTPSResults = [4]SmartTUNHTTPSResult{} },
	} {
		next := canceled
		mutate(&next)
		if validSmartTUNHTTPSEvidence(next, true) {
			t.Fatal("zero probes acquired measured evidence")
		}
	}
	r := supervisedExample(t, false)
	receipt := smartTUNReceipt(r, true, false)
	if receipt.HealthEvidenceVersion != 2 || receipt.HealthEvidence == nil || r.Supervised.Evidence != (SmartTUNHealthEvidence{}) {
		t.Fatal("unmeasured receipt lost its version or mutated the exact journal zero value")
	}
	for _, result := range receipt.HealthEvidence.HTTPSResults {
		if result != (SmartTUNHTTPSResult{Result: "not_run"}) {
			t.Fatal("unmeasured receipt implied HTTPS execution")
		}
	}
}

func TestSupervisedBothEvidenceVersionsKeepCommonStrictMembers(t *testing.T) {
	for _, record := range []smartTUNTrialJournal{supervisedExample(t, true), legacySupervisedExample(t, true)} {
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range []struct{ old, new string }{
			{`"supervised":{`, `"supervised":{"unknown":false,`},
			{`"evidence":{`, `"evidence":{"unknown":false,`},
			{`"underlay_healthy":true`, `"underlay_healthy":null`},
			{`"ipv4_tcp":true`, `"IPv4_TCP":true`},
			{`"ipv4_tcp":true`, `"ipv4_tcp":true,"ipv4_tcp":true`},
			{`"reason":"healthy"`, `"reason":null`},
		} {
			bad := strings.Replace(string(raw), change.old, change.new, 1)
			if bad == string(raw) {
				t.Fatalf("common strict mutation did not affect Version%d", record.Supervised.Version)
			}
			if _, err := decodeSmartTUNTrial([]byte(bad)); err == nil {
				t.Fatalf("Version%d relaxed common strict fields: %s", record.Supervised.Version, change.new)
			}
		}
	}
}
