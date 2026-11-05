//go:build linux

package sc

import (
	"errors"
	"strings"
	"testing"
)

func TestHostCaptureGateRequiresSameOperationAndKernelLifetime(t *testing.T) {
	ingress := hostIngressStageExample()
	ingress.SysctlBefore = 1
	barrier := hostBarrierExample()
	if err := validateHostCaptureGatePair(ingress, barrier); err != nil {
		t.Fatalf("valid common operation rejected: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*hostIngressStage, *hostNetworkBarrier)
	}{
		{"operation", func(_ *hostIngressStage, b *hostNetworkBarrier) {
			b.OperationID = strings.Repeat("b", 32)
			b.Name = "scq" + strings.Repeat("b", 12)
		}},
		{"boot", func(_ *hostIngressStage, b *hostNetworkBarrier) { b.BootID = "22222222-3333-4444-5555-666666666666" }},
		{"namespace dev", func(_ *hostIngressStage, b *hostNetworkBarrier) { b.NamespaceDev++ }},
		{"namespace ino", func(_ *hostIngressStage, b *hostNetworkBarrier) { b.NamespaceIno++ }},
		{"barrier replay", func(_ *hostIngressStage, b *hostNetworkBarrier) { b.Stage = "unexpected" }},
		{"corrupt ingress", func(i *hostIngressStage, _ *hostNetworkBarrier) { i.NFTStage = "observed" }},
		{"barrier null identity", func(_ *hostIngressStage, b *hostNetworkBarrier) { b.OperationID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, b := ingress, barrier
			tc.mutate(&i, &b)
			if err := validateHostCaptureGatePair(i, b); err == nil {
				t.Fatal("cross-operation or invalid kernel lifetime accepted")
			}
		})
	}
}

func TestHostCaptureGateCannotStartWithoutIndependentRecoveryAndSingleJournal(t *testing.T) {
	initial := hostCaptureGateProgress{Ingress: hostIngressStageExample(), Barrier: hostBarrierExample()}
	initial.Ingress.SysctlBefore = 1
	okGuard := func() error { return nil }
	okPersist := func(hostCaptureGateProgress, hostCaptureGateProgress) error { return nil }
	for _, tc := range []struct {
		name    string
		guard   func() error
		persist hostCaptureGatePersist
	}{
		{"no guard", nil, okPersist},
		{"no enclosing parent journal", okGuard, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := initial
			err := runHostCaptureGateLocked(nil, &current, tc.guard, tc.persist)
			if ErrorCode(err) != "guard_unavailable" || current != initial {
				t.Fatalf("unguarded start changed owner state: %v", err)
			}
		})
	}
}

func TestHostCaptureProgressAdaptersCompareWholeParentAndNeverAdvanceOnFailedDurability(t *testing.T) {
	initial := hostCaptureGateProgress{Ingress: hostIngressStageExample(), Barrier: hostBarrierExample()}
	initial.Ingress.SysctlBefore = 1
	current := initial
	writeCalls := 0
	rejected := errors.New("enclosing fsync refused")
	refuse := func(before, next hostCaptureGateProgress) error {
		writeCalls++
		if before != initial || (next.Ingress != initial.Ingress && next.Barrier != initial.Barrier) {
			t.Fatal("callback did not see exactly one full-parent component transition")
		}
		return rejected
	}
	nextIngress := current.Ingress
	nextIngress.SysctlStage = "effect_possible"
	if err := hostCaptureIngressPersistence(&current, refuse)(&initial.Ingress, nextIngress); !errors.Is(err, rejected) ||
		current != initial || writeCalls != 1 {
		t.Fatalf("failed ingress fsync advanced memory or lost error: %v", err)
	}
	staleIngress := initial.Ingress
	staleIngress.NFTStage = "effect_possible"
	if code := ErrorCode(hostCaptureIngressPersistence(&current, refuse)(&staleIngress, nextIngress)); code != "activation_journal_conflict" || writeCalls != 1 {
		t.Fatalf("stale ingress callback escaped CAS: %s", code)
	}
	newBarrier := current.Barrier
	newBarrier.Stage = "create_possible"
	if err := hostCaptureBarrierPersistence(&current, refuse)(initial.Barrier, newBarrier); !errors.Is(err, rejected) ||
		current != initial || writeCalls != 2 {
		t.Fatalf("failed barrier fsync advanced memory or lost error: %v", err)
	}
	accept := func(before, next hostCaptureGateProgress) error {
		if before != current || next.Ingress != initial.Ingress || next.Barrier != newBarrier {
			t.Fatal("successful barrier callback broke parent coupling")
		}
		return nil
	}
	if err := hostCaptureBarrierPersistence(&current, accept)(initial.Barrier, newBarrier); err != nil || current.Barrier != newBarrier {
		t.Fatalf("durable barrier progress not recorded: %v", err)
	}
	if code := ErrorCode(hostCaptureBarrierPersistence(&current, accept)(initial.Barrier, newBarrier)); code != "activation_journal_conflict" {
		t.Fatalf("stale barrier replay accepted: %s", code)
	}
}
