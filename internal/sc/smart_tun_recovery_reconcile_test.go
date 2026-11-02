package sc

import (
	"strings"
	"testing"
)

func idleRecoveryObservation() string {
	return "Id=" + trialRecoveryUnit + "\n" +
		"LoadState=loaded\nFragmentPath=" + trialGuardUnitDir + trialRecoveryUnit + "\n" +
		"DropInPaths=\nTransient=no\nUnitFileState=static\n" +
		"ActiveState=failed\nSubState=failed\nResult=exit-code\n" +
		"MainPID=0\nControlPID=0\nJob=\nControlGroup=\n"
}

func TestParseSmartTUNIdleRecoveryServiceExactProof(t *testing.T) {
	failed := idleRecoveryObservation()
	if got, err := parseSmartTUNIdleRecoveryService([]byte(failed)); err != nil || !got {
		t.Fatalf("trusted, quiescent FAILED rejected: failed=%v err=%v", got, err)
	}
	healthy := strings.Replace(
		strings.Replace(
			strings.Replace(failed, "ActiveState=failed", "ActiveState=inactive", 1),
			"SubState=failed", "SubState=dead", 1),
		"Result=exit-code", "Result=success", 1)
	if got, err := parseSmartTUNIdleRecoveryService([]byte(healthy)); err != nil || got {
		t.Fatalf("trusted, inactive SUCCESS rejected: failed=%v err=%v", got, err)
	}
	for _, result := range []string{"timeout", "signal", "core-dump"} {
		t.Run("known_failure_"+result, func(t *testing.T) {
			data := strings.Replace(failed, "Result=exit-code", "Result="+result, 1)
			if got, err := parseSmartTUNIdleRecoveryService([]byte(data)); err != nil || !got {
				t.Fatalf("known systemd failure rejected: %v %v", got, err)
			}
		})
	}
	rejected := map[string]string{
		"still active":                     strings.Replace(failed, "ActiveState=failed", "ActiveState=active", 1),
		"activating":                       strings.Replace(failed, "ActiveState=failed", "ActiveState=activating", 1),
		"unknown failure result":           strings.Replace(failed, "Result=exit-code", "Result=watchdog", 1),
		"start rate limit":                 strings.Replace(failed, "Result=exit-code", "Result=start-limit-hit", 1),
		"main PID":                         strings.Replace(failed, "MainPID=0", "MainPID=157", 1),
		"noncanonical main PID":            strings.Replace(failed, "MainPID=0", "MainPID=00", 1),
		"control PID":                      strings.Replace(failed, "ControlPID=0", "ControlPID=412", 1),
		"pending job":                      strings.Replace(failed, "Job=\n", "Job=123\n", 1),
		"residual cgroup":                  strings.Replace(failed, "ControlGroup=\n", "ControlGroup=/system.slice/server-connect-activation-recover.service\n", 1),
		"wrong unit name":                  strings.Replace(failed, "Id="+trialRecoveryUnit, "Id=another.service", 1),
		"wrong fragment":                   strings.Replace(failed, "FragmentPath=/etc/", "FragmentPath=/run/", 1),
		"dropin present":                   strings.Replace(failed, "DropInPaths=\n", "DropInPaths=/run/override.conf\n", 1),
		"transient":                        strings.Replace(failed, "Transient=no", "Transient=yes", 1),
		"service enabled":                  strings.Replace(failed, "UnitFileState=static", "UnitFileState=enabled", 1),
		"bad load":                         strings.Replace(failed, "LoadState=loaded", "LoadState=not-found", 1),
		"mismatched substate":              strings.Replace(failed, "SubState=failed", "SubState=dead", 1),
		"missing line":                     strings.Replace(failed, "ControlPID=0\n", "", 1),
		"duplicate empty line":             failed + "Job=\n",
		"duplicate nonempty line":          failed + "MainPID=0\n",
		"unknown field":                    failed + "ManagerOverride=yes\n",
		"malformed line":                   failed + "injected\n",
		"negative PID":                     strings.Replace(failed, "MainPID=0", "MainPID=-1", 1),
		"untrusted success":                strings.Replace(failed, "Result=exit-code", "Result=success", 1),
		"fail state with healthy substate": strings.Replace(failed, "SubState=failed", "SubState=dead", 1),
		"empty":                            "",
		"oversized":                        strings.Repeat("x", 16385),
	}
	for name, candidate := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSmartTUNIdleRecoveryService([]byte(candidate)); err == nil {
				t.Fatal("unsafe recovery executor state accepted")
			}
		})
	}
}

func TestParseSmartTUNIdleRecoveryServiceNoImplicitTransition(t *testing.T) {
	// Pure observation cannot convert a failed recovery into operational
	// authority; only explicit owner-requested reconciliation can call reset.
	raw := idleRecoveryObservation()
	before := raw
	for i := 0; i < 2; i++ {
		failed, err := parseSmartTUNIdleRecoveryService([]byte(raw))
		if err != nil || !failed {
			t.Fatal("failed guard silently became ready on repeated observation")
		}
	}
	if raw != before {
		t.Fatal("observer mutated failed service evidence")
	}
}

func TestRejectSmartTUNOrphanedTables(t *testing.T) {
	safe := []map[string]any{{"table": map[string]any{"family": "inet", "name": "scqa_foreign_validation"}}}
	if err := rejectSmartTUNOrphanedTables(safe); err != nil {
		t.Fatalf("unrelated foreign nft table was treated as product owned: %v", err)
	}
	for name, object := range map[string]map[string]any{
		"orphan_previous_operation": {"table": map[string]any{"family": "inet", "name": "scnt_14e427fefd9a237a69eb91d919a8e8c8"}},
		"wrong_typed_table":         {"table": "malformed"},
		"missing_table_name":        {"table": map[string]any{"family": "inet"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectSmartTUNOrphanedTables([]map[string]any{object}); err == nil {
				t.Fatal("unsafe native nft observation was accepted")
			}
		})
	}
}

func TestManagedRecoveryObserverDoesNotWidenHealthOrArbitraryUnitScope(t *testing.T) {
	for _, role := range []string{trialRecoveryUnit, trialRecoveryTimer} {
		if _, _, err := observeSmartTUNHealthUnit(role); ErrorCode(err) != "guard_unavailable" {
			t.Fatalf("health observer accepted recovery role %s: %v", role, err)
		}
	}
	for _, role := range []string{smartTUNHealthUnit, smartTUNHealthTimer, "untrusted.service", ""} {
		if _, _, err := observeSmartTUNRecoveryUnit(role); ErrorCode(err) != "guard_unavailable" {
			t.Fatalf("recovery observer accepted other role %s: %v", role, err)
		}
	}
	if _, _, err := observeSmartTUNManagedUnit("untrusted.service"); ErrorCode(err) != "guard_unavailable" {
		t.Fatalf("managed observer accepted untrusted unit: %v", err)
	}
}

// A failed Health oneshot and a failed Recovery oneshot may coexist after a
// TCG timeout even though the Guard has restored all native resources. Both
// must be proved quiescent before either FAILED bookkeeping record is reset.
func TestParseSmartTUNIdleHealthServiceExactProof(t *testing.T) {
	failed := strings.ReplaceAll(idleRecoveryObservation(), trialRecoveryUnit, smartTUNHealthUnit)
	for _, state := range []string{"exit-code", "timeout", "signal", "core-dump"} {
		raw := strings.Replace(failed, "Result=exit-code", "Result="+state, 1)
		if got, err := parseSmartTUNIdleManagedService([]byte(raw), smartTUNHealthUnit); err != nil || !got {
			t.Fatalf("quiescent failed Health %s rejected: %v %v", state, got, err)
		}
	}
	healthy := strings.NewReplacer("ActiveState=failed", "ActiveState=inactive",
		"SubState=failed", "SubState=dead", "Result=exit-code", "Result=success").Replace(failed)
	if got, err := parseSmartTUNIdleManagedService([]byte(healthy), smartTUNHealthUnit); err != nil || got {
		t.Fatalf("idle healthy Health rejected: %v %v", got, err)
	}
	for name, raw := range map[string]string{
		"running unit":                 strings.Replace(failed, "ActiveState=failed", "ActiveState=active", 1),
		"still-activating":             strings.Replace(failed, "ActiveState=failed", "ActiveState=activating", 1),
		"live main PID":                strings.Replace(failed, "MainPID=0", "MainPID=314", 1),
		"queued systemd job":           strings.Replace(failed, "Job=\n", "Job=42\n", 1),
		"nonempty cgroup":              strings.Replace(failed, "ControlGroup=\n", "ControlGroup=/system.slice/server-connect-smart-health.service\n", 1),
		"other unit id":                strings.Replace(failed, "Id="+smartTUNHealthUnit, "Id="+trialRecoveryUnit, 1),
		"other unit path":              strings.Replace(failed, "FragmentPath=/etc/systemd/system/", "FragmentPath=/run/systemd/system/", 1),
		"unknown result":               strings.Replace(failed, "Result=exit-code", "Result=start-limit-hit", 1),
		"failed with healthy substate": strings.Replace(failed, "SubState=failed", "SubState=dead", 1),
		"unapproved drop-in":           strings.Replace(failed, "DropInPaths=\n", "DropInPaths=/tmp/override.conf\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSmartTUNIdleManagedService([]byte(raw), smartTUNHealthUnit); ErrorCode(err) != "guard_unavailable" {
				t.Fatalf("unsafe Health service state accepted: %v", err)
			}
		})
	}
	if _, err := parseSmartTUNIdleManagedService([]byte(failed), trialRecoveryUnit); err == nil {
		t.Fatal("Health identity was accepted as Recovery authority")
	}
	if _, err := parseSmartTUNIdleManagedService([]byte(idleRecoveryObservation()), smartTUNHealthUnit); err == nil {
		t.Fatal("Recovery identity was accepted as Health authority")
	}
	if _, err := parseSmartTUNIdleManagedService([]byte(failed), "ssh.service"); err == nil {
		t.Fatal("arbitrary foreign systemd service accepted as owned Health")
	}
}
