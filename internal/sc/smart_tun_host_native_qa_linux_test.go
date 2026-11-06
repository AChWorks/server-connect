//go:build linux

package sc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostNativeLinkPlanBindsTheSameIngressAndNativeOperation(t *testing.T) {
	progress := hostCaptureJournalExample().Progress
	planned, err := newHostNativeLinkPlan(progress, "sctunv70")
	if err != nil {
		t.Fatal(err)
	}
	if planned.Native.NFTName != "scnt_"+progress.Ingress.OperationID ||
		planned.Native.NamespaceIno != progress.Ingress.NamespaceIno ||
		planned.Native.UnderlayIndex != progress.Ingress.UnderlayIndex ||
		planned.Native.LinkStage != "planned" || planned.Native.IPv4.Address != "172.31.99.1/30" ||
		planned.Native.IPv6.Address != "" || planned.Native.NFT.Stage != "planned" {
		t.Fatal("host native preparation created an unbound or routed transaction")
	}
	for _, name := range []string{"", "lo", progress.Ingress.Underlay, progress.Barrier.Name, "invalid/if", strings.Repeat("x", 32)} {
		if _, err := newHostNativeLinkPlan(progress, name); err == nil {
			t.Fatalf("invalid or foreign native link admitted: %q", name)
		}
	}
}

func TestHostNativeTwoPassPrerequisitesPreserveRelevantBaseline(t *testing.T) {
	a := hostNativeExample()
	b := a
	b.Progress.Ingress.OperationID = strings.Repeat("f", 32)
	b.Progress.Barrier.OperationID = b.Progress.Ingress.OperationID
	b.Progress.Barrier.Name = "scq" + b.Progress.Ingress.OperationID[:12]
	b.Native.NFTName = "scnt_" + b.Progress.Ingress.OperationID
	if !sameHostNativePrerequisites(a, b) {
		t.Fatal("fresh operation identity should not cause false prearm conflict")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*hostNativeJournal)
	}{
		{"underlay", func(r *hostNativeJournal) { r.Progress.Ingress.Underlay = "foreign0" }},
		{"index", func(r *hostNativeJournal) { r.Progress.Ingress.UnderlayIndex++ }},
		{"namespace", func(r *hostNativeJournal) { r.Progress.Barrier.NamespaceIno++ }},
		{"raw", func(r *hostNativeJournal) { r.Progress.Ingress.RawSHA256 = strings.Repeat("a", 64) }},
		{"sysctl", func(r *hostNativeJournal) { r.Progress.Ingress.SysctlBefore = 0 }},
		{"boot", func(r *hostNativeJournal) { r.Progress.Ingress.BootID = "22222222-3333-4444-5555-666666666666" }},
		{"native-slot", func(r *hostNativeJournal) { r.Native.IPv4.Table++ }},
		{"tunnel", func(r *hostNativeJournal) { r.TunnelInterface = "newlink0" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := b
			tc.mutate(&changed)
			if sameHostNativePrerequisites(a, changed) {
				t.Fatal("changed prearm baseline was accepted")
			}
		})
	}
}

func TestHostNativeQAInvalidRequestNeverArmsOrCreatesState(t *testing.T) {
	for _, point := range []string{"", "after-journal", "after-ingress", "after-barrier", "after-verified", "after-native-link-bind", "after-native-persist"} {
		if !hostNativeQAKillAllowed(point) {
			t.Fatalf("supported v7 crash boundary rejected: %s", point)
		}
	}
	for _, point := range []string{"after-native-nft-effect", "after-native-capture", "after-start", "after-native-route-effect", "unknown"} {
		if hostNativeQAKillAllowed(point) {
			t.Fatalf("native QA accepted routing or unknown crash boundary %s", point)
		}
	}
	requests := []struct {
		name, peer, underlay, tunnel, point string
		deadline                            int
	}{
		{"unsupported-paths", "8.8.8.8", "eth0", "sctunv70", "", 120},
		{"bad-point", "8.8.8.8", "eth0", "sctunv70", "after-start", 120},
		{"missing-peer", "", "eth0", "sctunv70", "", 120},
		{"bad-underlay", "8.8.8.8", "lo", "sctunv70", "", 120},
		{"expired-deadline", "8.8.8.8", "eth0", "sctunv70", "", 3},
	}
	for _, tc := range requests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "not-created")
			m := New(path, DefaultCore, DefaultPort)
			called := false
			receipt, err := m.runHostNativeLinkQAWithPrearm(tc.peer, tc.underlay, tc.tunnel, tc.deadline, tc.point, func() error { called = true; return nil })
			if err == nil || called || receipt.ActivationReady || receipt.RecoveryVerified || !receipt.ExperimentOnly || !receipt.NativeLinkOnly || receipt.KernelBarrierClosed || receipt.GuardScheduled {
				t.Fatalf("invalid v7 QA armed a Guard or claimed activation: %+v %v", receipt, err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid QA changed filesystem: %v", err)
			}
		})
	}
}

func TestHostNativeLinkReceiptDoesNotClaimVPNOrRouting(t *testing.T) {
	receipt := HostCapturePreparationQAReceipt{Phase: "native_link_prepared_pending_independent_recovery", NativeLinkOnly: true, ExperimentOnly: true, KernelBarrierClosed: true, GuardScheduled: true}
	if receipt.ActivationReady || receipt.RecoveryVerified || !receipt.NativeLinkOnly || !receipt.ExperimentOnly {
		t.Fatal("link-only preparation was misrepresented as active VPN")
	}
}
