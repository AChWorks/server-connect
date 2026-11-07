//go:build linux

package sc

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Rootless E2E is explicitly injected into a fresh network namespace with
// the real official sing-box Core; never run recovery on the test host.
func TestNativeRedirectStoppedCoreGuest(t *testing.T) {
	if os.Getenv("SC_NATIVE_RECOVERY_GUEST") != "yes" {
		t.Skip("requires isolated, owned network namespace")
	}
	p := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	err := recoverNativeRedirect(context.Background(), nativeSystemRunner{}, p)
	if os.Getenv("SC_NATIVE_RECOVERY_EXPECT_REFUSAL") == "yes" {
		if err == nil {
			t.Fatal("foreign route accepted for destructive cleanup")
		}
		if !strings.Contains(err.Error(), "unexpected redirect-table route") {
			t.Fatalf("wrong collision classification: %v", err)
		}
		t.Log("FOREIGN_COLLISION_REFUSAL=PASS")
		return
	}
	if err != nil {
		t.Fatalf("Core SIGKILL recovery failed: %v", err)
	}
	t.Log("ROOTLESS_CRASH_DIRECT_BASELINE_RECOVERED=PASS")
	if err := recoverNativeRedirect(context.Background(), nativeSystemRunner{}, p); err != nil {
		t.Fatalf("already-clean native recovery must remain idempotent: %v", err)
	}
	t.Log("ROOTLESS_NATIVE_CLEAN_RETRY=PASS")
}

type unexpectedNativeRunner struct{ actions int }

func (r *unexpectedNativeRunner) output(_ context.Context, bin string, args ...string) (string, error) {
	key := bin + " " + strings.Join(args, " ")
	switch key {
	case "ip -4 rule show":
		return "0:\tfrom all lookup local\n1:\tfrom all lookup 555\n1:\tfrom all lookup 777\n32766:\tfrom all lookup main\n", nil
	case "ip -6 rule show":
		return "0:\tfrom all lookup local\n", nil
	}
	return "", nil
}
func (r *unexpectedNativeRunner) run(_ context.Context, _ string, _ ...string) error {
	r.actions++
	return nil
}
func TestNativeRedirectDuplicatePriorityNeverMutates(t *testing.T) {
	r := &unexpectedNativeRunner{}
	err := recoverNativeRedirect(context.Background(), r, nativeRedirectRecovery{
		TunnelIF: "sctun0", UnderlayIF: "scouter0", Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex,
	})
	if err == nil || r.actions != 0 {
		t.Fatalf("expected no destructive actions, err=%v count=%d", err, r.actions)
	}
}
