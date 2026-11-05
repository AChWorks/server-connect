//go:build linux

package sc

import (
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

func TestHostCaptureGateCannotStartWithoutIndependentRecoveryAndBothJournals(t *testing.T) {
	ingress := hostIngressStageExample()
	ingress.SysctlBefore = 1
	barrier := hostBarrierExample()
	okGuard := func() error { return nil }
	okIngress := func(*hostIngressStage, hostIngressStage) error { return nil }
	okBarrier := func(hostNetworkBarrier, hostNetworkBarrier) error { return nil }
	for _, tc := range []struct {
		name  string
		guard func() error
		pi    hostIngressPersist
		pb    hostNetworkBarrierPersist
	}{
		{"no guard", nil, okIngress, okBarrier},
		{"no ingress journal", okGuard, nil, okBarrier},
		{"no barrier journal", okGuard, okIngress, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, b := ingress, barrier
			err := runHostCaptureGateLocked(nil, &i, &b, tc.guard, tc.pi, tc.pb)
			if ErrorCode(err) != "guard_unavailable" || i != ingress || b != barrier {
				t.Fatalf("unguarded start changed owner state: %v", err)
			}
		})
	}
}
