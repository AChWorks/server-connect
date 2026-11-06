//go:build linux

package sc

// This is a root-only, isolated-netns integration of the real pinned
// sing-box process with the v9 host-policy parent and kernel. It intentionally
// uses a test-only blocked outbound: it proves native Core attachment,
// ordering and recovery, NOT selected-VPN delivery or general-host Apply.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Core subprocess I/O can race diagnostic failures; do not inspect a
// concurrently written bytes.Buffer without synchronization.
type hostRouteCoreOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *hostRouteCoreOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(data)
}

func (o *hostRouteCoreOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func TestHostRouteV9ActualSingBoxCoreGuardedOff(t *testing.T) {
	if os.Getenv("SC_TEST_HOST_ROUTE_REAL_CORE") != "isolated-netns" {
		t.Skip("NOT_RUN: explicitly isolated root network namespace required")
	}
	crashMode := os.Getenv("SC_TEST_HOST_ROUTE_REAL_CORE_CRASH")
	if crashMode != "" && crashMode != "after-policy-receipt" {
		t.Fatal("unsupported actual-Core crash injection")
	}
	core := os.Getenv("SC_TEST_SINGBOX")
	if core == "" || !filepath.IsAbs(core) {
		t.Fatal("pinned real sing-box path required for explicit native Core test")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("NOT_RUN: this isolated official Core digest is pinned for Linux amd64 only")
	}
	f, err := os.Open(core)
	if err != nil {
		t.Fatal(err)
	}
	digestOfCore := sha256.New()
	_, copyErr := io.Copy(digestOfCore, f)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil ||
		hex.EncodeToString(digestOfCore.Sum(nil)) != "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93" {
		t.Fatal("actual sing-box Core is not the pinned official 1.14.3-linux-amd64 executable")
	}
	which, err := exec.Command(core, "version").CombinedOutput()
	if err != nil || !strings.HasPrefix(string(which), "sing-box version 1.14.3\n") {
		t.Fatalf("unsupported real Core version: %v", err)
	}

	guard, base := prepareHostNativeKernelFixture(t)
	// The official Core's Linux default-interface observation needs a
	// disposable underlay. No route or link escapes this fresh netns.
	ingressNativeCommand(t, "/usr/sbin/ip", "address", "add", "198.18.0.1/30", "dev", "scv7edge0")
	ingressNativeCommand(t, "/usr/sbin/ip", "address", "add", "198.18.0.2/30", "dev", "scv7edge1")
	ingressNativeCommand(t, "/usr/sbin/ip", "link", "set", "scv7edge1", "up")
	ingressNativeCommand(t, "/usr/sbin/ip", "route", "add", "default", "via", "198.18.0.2", "dev", "scv7edge0")
	before := hostNativeKernelSnapshot(t)

	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	// One genuine, deliberately non-VPN Core configuration; selected VLESS
	// path acceptance is a separate endpoint- and wire-bound test.
	config := []byte(`{"log":{"level":"warn"},"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"sctunv70","address":[],"mtu":1400,"stack":"gvisor","auto_route":false,"auto_redirect":false}],"outbounds":[{"type":"block","tag":"blocked"}],"route":{"final":"blocked"}}`)
	r.Core.ConfigSHA256 = sha256Hex(config)
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	if err := validateHostRouteJournal(r); err != nil {
		t.Fatal(err)
	}

	dir := privateJournalTempDir(t)
	m := New(dir, core, DefaultPort)
	var process *exec.Cmd
	var output hostRouteCoreOutput
	var processExit chan error
	processActive := false
	t.Cleanup(func() {
		if process != nil && process.Process != nil && processActive {
			_ = process.Process.Kill()
			select {
			case <-processExit:
			case <-time.After(5 * time.Second):
				t.Error("test-owned Core did not terminate")
			}
		}
	})

	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := writeHostRouteJournal(store, r, nil); err != nil {
			return err
		}
		if err := runHostCaptureGateLocked(store, &r.Progress, guard, hostRouteCapturePersist(store, &r)); err != nil {
			return fmt.Errorf("ingress: %w", err)
		}
		native := r.nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostRouteNativePersist(store, &r)); err != nil {
			return fmt.Errorf("link: %w", err)
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, config, nil); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_staged"); err != nil {
			return err
		}
		if check, err := exec.Command(core, "check", "-c", filepath.Join(dir, smartTUNTrialConfigFile)).CombinedOutput(); err != nil {
			return fmt.Errorf("official Core config rejected: %v: %s", err, check)
		}
		watch, err := nativeTUNWatchStart(r.nativeView())
		if err != nil {
			return err
		}
		defer watch.close()
		if err := hostRouteCoreStagePersist(store, &r, "start_requested"); err != nil {
			return err
		}
		process = exec.Command(core, "run", "-c", filepath.Join(dir, smartTUNTrialConfigFile))
		process.Stdout, process.Stderr = &output, &output
		process.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		if err := process.Start(); err != nil {
			return fmt.Errorf("real Core start failed: %w", err)
		}
		processActive = true
		processExit = make(chan error, 1)
		go func() { processExit <- process.Wait() }()
		if err := watch.verify(r.nativeView()); err != nil {
			return fmt.Errorf("real Core native TUN attach unverified: %w", err)
		}
		select {
		case exit := <-processExit:
			processActive = false
			return fmt.Errorf("real Core exited after attach: %v: %s", exit, output.String())
		default:
		}
		if err := hostRouteCoreStagePersist(store, &r, "active_observed"); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "effect_possible"); err != nil {
			return err
		}
		native = r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return fmt.Errorf("native policy with real Core: %w", err)
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		if r.Route.State != "observed" || r.Core.Stage != "active_observed" ||
			r.Native.IPv4.Rule.Stage != "observed" || r.Native.NFT.Stage != "observed" {
			return errors.New("real Core routing and guard were not receipted in one durable v9 parent")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("v9 real-core admission failed: %v: %s", err, output.String())
	}
	fmt.Println("HOST_ROUTE_V9_REAL_PINNED_CORE_ATTACHED_WITH_GUARDED_POLICY=PASS")
	if crashMode == "after-policy-receipt" {
		// Actual process death must not retire its durable FIB/RPDB/nft
		// receipts, stop the independent containment, or grant false Off.
		if err := process.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		select {
		case <-processExit:
		case <-time.After(5 * time.Second):
			t.Fatal("real sing-box process failed to die after SIGKILL")
		}
		processActive = false
		observed, err := hostRouteNFTObserver(&r)(r.nativeView())
		if err != nil || !observed.Matches ||
			!nativeTUNNFTReceiptCovers(r.nativeView(), observed, true) {
			t.Fatal("real Core SIGKILL lost independent nft final-egress guard")
		}
		fmt.Println("HOST_ROUTE_V9_REAL_CORE_SIGKILL_RETAINED_ROUTED_GUARD=PASS")
	}

	state := smartTUNCoreObservationExample("active")
	inactive := smartTUNCoreObservationExample("inactive")
	inactive.identity = state.identity
	stopCount := 0
	services := hostCoreRecoveryServices{
		observe: func() (smartTUNTrialUnitObservation, error) {
			if processActive {
				return state, nil
			}
			return inactive, nil
		},
		stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
			if !started || !valid {
				return errors.New("real Core lacks durable start or credential authority")
			}
			// The routed native kernel policy must still be present when
			// independent Core-first recovery requests quiescence.
			route, _, err := nativeTUNObserveResource(r.nativeView(), 4, "rule")
			if err != nil || !route {
				return errors.New("RPDB removed before real Core quiescence")
			}
			if processActive {
				if err := process.Process.Signal(syscall.SIGTERM); err != nil {
					return fmt.Errorf("real Core stop signal: %w", err)
				}
				select {
				case <-processExit:
				case <-time.After(5 * time.Second):
					return errors.New("real Core did not stop within bounded recovery")
				}
				processActive = false
			} else if crashMode != "after-policy-receipt" {
				return errors.New("real Core stopped without authorized crash boundary")
			}
			stopCount++
			return nil
		},
	}
	receipt, err := m.recoverGuardedTrialWithHandler("", "", func(store *activationJournalDir, s trialRecoverySelection) (TrialReceipt, error) {
		if s.version != hostRouteJournalVersion || s.hostRoute.Route.State != "observed" {
			return TrialReceipt{}, errors.New("independent Recovery did not select exact real-Core v9 operation")
		}
		return recoverHostRouteJournalLocked(store, &s.hostRoute, services)
	})
	if err != nil || !receipt.RecoveryVerified || stopCount != 1 {
		t.Fatalf("real Core-first v9 recovery failed: %+v %v: %s", receipt, err, output.String())
	}
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		return clearRecoveredHostRouteLocked(store, r.Progress.Ingress.OperationID, services)
	}); err != nil {
		t.Fatal(err)
	}
	beforeStructural, beforeCounters := hostRouteRealCoreKernelSnapshot(t, before)
	afterStructural, afterCounters := hostRouteRealCoreKernelSnapshot(t, hostNativeKernelSnapshot(t))
	if beforeStructural != afterStructural || len(beforeCounters) != len(afterCounters) {
		t.Fatal("real Core v9 Off changed foreign kernel structure, FIB, RPDB or counter inventory")
	}
	for i, value := range beforeCounters {
		if afterCounters[i] < value {
			t.Fatal("real Core v9 Off reset or reduced a foreign nft packet/byte counter")
		}
	}
	if crashMode == "after-policy-receipt" {
		fmt.Println("HOST_ROUTE_V9_REAL_CORE_SIGKILL_INDEPENDENT_OFF=PASS")
	} else {
		fmt.Println("HOST_ROUTE_V9_REAL_CORE_FIRST_OFF_AND_FOREIGN_KERNEL_BASELINE=PASS")
	}
}

// Real Core startup may originate a route probe on its disposable underlay.
// Only monotonic nft rule packet/byte counters are allowed to change; exact
// FIB/RPDB plus full nft object structure/handles/rule order must still match.
func hostRouteRealCoreKernelSnapshot(t *testing.T, snapshot string) (string, []uint64) {
	t.Helper()
	parts := strings.Split(snapshot, "\x00")
	if len(parts) != 5 {
		t.Fatal("incomplete isolated kernel route/rule/nft snapshot")
	}
	dec := json.NewDecoder(strings.NewReader(parts[4]))
	dec.UseNumber()
	var root map[string]any
	if err := dec.Decode(&root); err != nil {
		t.Fatal(err)
	}
	items, ok := root["nftables"].([]any)
	if !ok {
		t.Fatal("native nft snapshot objects missing")
	}
	var counters []uint64
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatal("unsupported native nft object")
		}
		rule, present := row["rule"]
		if !present {
			continue
		}
		details, ok := rule.(map[string]any)
		if !ok {
			t.Fatal("unsupported native nft rule")
		}
		exprs, ok := details["expr"].([]any)
		if !ok {
			t.Fatal("native nft rule expressions missing")
		}
		for _, expr := range exprs {
			mapping, ok := expr.(map[string]any)
			if !ok {
				t.Fatal("unsupported native nft expression")
			}
			raw, present := mapping["counter"]
			if !present {
				continue
			}
			counter, ok := raw.(map[string]any)
			if !ok || len(counter) != 2 {
				t.Fatal("unsupported native nft counter")
			}
			for _, field := range []string{"packets", "bytes"} {
				n, ok := counter[field].(json.Number)
				if !ok {
					t.Fatal("native nft counter not numeric")
				}
				value, err := strconv.ParseUint(n.String(), 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				counters = append(counters, value)
				counter[field] = json.Number("0")
			}
		}
	}
	normalized, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	parts[4] = string(normalized)
	return strings.Join(parts, "\x00"), counters
}
