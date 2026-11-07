//go:build linux

package sc

// This opt-in regression is deliberately red while native recovery deletes a
// same-shape foreign replacement. A successful reproduction is NOT product
// acceptance. It never changes production recovery or manufactures a receipt.
// Each case runs in a fresh unshared network namespace; the separately spawned
// replacer owns every synthetic foreign object involved in the experiment.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const ownershipABAOptIn = "SC_TEST_NATIVE_OWNERSHIP_ABA"

func TestNativeOwnershipABAPreservesForeignReplacement(t *testing.T) {
	if os.Getenv(ownershipABAOptIn) != "isolated-netns" {
		t.Skip("NOT_RUN: explicit disposable native ownership regression required")
	}
	selected := os.Getenv("SC_TEST_NATIVE_OWNERSHIP_ABA_CASE")
	if selected == "" {
		if os.Geteuid() != 0 {
			t.Fatal("root is required to create disposable network namespaces")
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		before := hostNativeKernelSnapshot(t) // Read-only initial-host witness.
		defer func() {
			after := hostNativeKernelSnapshot(t)
			fmt.Printf("OWNERSHIP_ABA_INITIAL_HOST_BEFORE_SHA256=%s\nOWNERSHIP_ABA_INITIAL_HOST_AFTER_SHA256=%s\n", sha256Hex([]byte(before)), sha256Hex([]byte(after)))
			if before != after {
				t.Error("initial-host network structure changed during isolated reproduction")
			}
		}()
		for _, kind := range []string{"rule", "route"} {
			for _, timing := range []string{"before-recovery", "after-last-observation"} {
				name := kind + "/" + timing
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					defer cancel()
					cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "--net", "--", executable,
						"-test.run=^TestNativeOwnershipABAPreservesForeignReplacement$", "-test.v", "-test.timeout=40s")
					cmd.Env = append(os.Environ(), "SC_TEST_NATIVE_OWNERSHIP_ABA_CASE="+name)
					out, err := cmd.CombinedOutput()
					t.Logf("isolated witness:\n%s", out)
					if err != nil {
						t.Errorf("foreign-resource preservation invariant failed: %v", err)
					}
				})
			}
		}
		return
	}
	parts := strings.Split(selected, "/")
	if len(parts) != 2 || (parts[0] != "rule" && parts[0] != "route") ||
		(parts[1] != "before-recovery" && parts[1] != "after-last-observation") {
		t.Fatal("unsupported ownership reproduction case")
	}
	kind, timing := parts[0], parts[1]
	self := requireNativeQANetworkNamespace(t)
	links := ingressNativeCommand(t, "/usr/sbin/ip", "-j", "link", "show")
	var parsed []map[string]json.RawMessage
	if json.Unmarshal([]byte(links), &parsed) != nil || len(parsed) != 1 {
		t.Fatal("ownership reproduction requires a fresh namespace containing only loopback")
	}
	fmt.Printf("OWNERSHIP_ABA_CASE=%s NAMESPACE=%v\n", selected, self.Sys())
	guard, base := prepareHostNativeKernelFixture(t)
	r := hostRouteKernelExample(t)
	r.Progress, r.Native = base.Progress, base.Native
	r.Native.NFTName = "scnt_" + r.Progress.Ingress.OperationID
	digest, err := hostRoutePolicyPlanSHA256(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Route.PolicySHA256 = digest
	manager := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
	err = manager.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := hostRouteKernelReady(t, store, &r, guard, []byte(`{"simulated":"host-route-v9"}`)); err != nil {
			return err
		}
		native := r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		// Read the strict, fsynced parent back before the foreign owner acts.
		durable, _, err := loadHostRouteJournal(store)
		if err != nil || durable != r {
			return errors.New("durable receipt readback failed")
		}
		receipt := *nativeTUNResource(&durable.Native, 4, kind)
		if receipt.Stage != "observed" || receipt.SHA256 == "" {
			return errors.New("target has no durable observed receipt")
		}
		original := ownershipABAObject(t, kind)
		if len(original) == 0 {
			return errors.New("independent reader did not find the original object")
		}
		fmt.Printf("OWNERSHIP_ABA_DURABLE_RECEIPT kind=%s sha256=%s independent_shape=%s\n", kind, receipt.SHA256, original)

		// A noncolliding concurrent manager remains a separate owner. Its
		// resources are independently compared after the target operation.
		ingressNativeCommand(t, "/usr/sbin/ip", "-4", "route", "add", "198.18.100.0/24", "dev", "scv7edge0", "table", "29999", "protocol", "99")
		ingressNativeCommand(t, "/usr/sbin/ip", "-4", "rule", "add", "priority", "20000", "fwmark", "0x12000000/0xff000000", "table", "29999", "protocol", "99")
		foreignBefore := ownershipABADisjoint(t)

		// Follow the actual Core-first recovery prefix. Core service state is
		// simulated, as in the v9 kernel tests; kernel objects are genuine.
		if err := hostRoutePhasePersist(store, &r, "off_pending"); err != nil {
			return err
		}
		active := smartTUNCoreObservationExample("active")
		inactive := smartTUNCoreObservationExample("inactive")
		inactive.identity = active.identity
		services := hostCoreRecoveryServices{
			observe: func() (smartTUNTrialUnitObservation, error) { return active, nil },
			stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
				if !started || !valid {
					return errors.New("Core stop authority missing")
				}
				active = inactive
				return nil
			},
		}
		if err := hostCoreStopWith(store, &r.Core, func(stage string) error { return hostRouteCoreStagePersist(store, &r, stage) }, services); err != nil {
			return err
		}
		replaced, replacementComplete := false, false
		replace := func() error {
			if replaced {
				return errors.New("replacement callback ran twice")
			}
			replaced = true
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			ns, err := os.Readlink("/proc/self/ns/net")
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestNativeOwnershipABAReplacementHelper$", "-test.v", "-test.timeout=8s")
			cmd.Env = append(os.Environ(), "SC_TEST_NATIVE_OWNERSHIP_ABA_REPLACER="+kind, "SC_TEST_NATIVE_OWNERSHIP_ABA_NAMESPACE="+ns)
			out, err := cmd.CombinedOutput()
			fmt.Printf("OWNERSHIP_ABA_INDEPENDENT_HELPER:\n%s", out)
			if err != nil {
				return fmt.Errorf("independent replacement failed: %w", err)
			}
			if after := ownershipABAObject(t, kind); !bytes.Equal(original, after) {
				return errors.New("replacement is not byte-identical in independent normalized JSON")
			}
			present, hash, err := nativeTUNObserveResource(r.nativeView(), 4, kind)
			if err != nil || !present || hash != receipt.SHA256 {
				return errors.New("replacement did not reproduce the receipt's attribute hash")
			}
			replacementComplete = true
			fmt.Printf("OWNERSHIP_ABA_REPLACEMENT_SAME_RECEIPT=%s\n", hash)
			return nil
		}
		if timing == "before-recovery" {
			if err := replace(); err != nil {
				return err
			}
		}
		native = r.nativeView()
		observe := hostRouteNFTObserver(&r)
		if err := nativeTUNCheckRecoveryGraphWithObserver(native, observe); err != nil {
			return err
		}
		if timing == "after-last-observation" {
			observe = func(view smartTUNTrialJournal) (nativeTUNNFTObservation, error) {
				// RemoveResource has already made its final RPDB/FIB
				// observation before requesting this guard observation.
				observed, err := hostRouteNFTObserver(&r)(view)
				if err != nil {
					return observed, err
				}
				if err := replace(); err != nil {
					return observed, err
				}
				return observed, nil
			}
		}
		removeErr := nativeTUNRemoveResourceWithObserver(store, &native, 4, kind, "", hostRouteNativePersist(store, &r), observe)
		if !replacementComplete {
			return fmt.Errorf("foreign writer did not complete at the requested boundary: %v", removeErr)
		}
		after := ownershipABAObject(t, kind)
		if disjointAfter := ownershipABADisjoint(t); disjointAfter != foreignBefore {
			t.Error("unrelated concurrent owner's disjoint resources changed")
		}
		fmt.Printf("OWNERSHIP_ABA_DISJOINT_FOREIGN_SHA256=%s\n", sha256Hex([]byte(foreignBefore)))
		fmt.Printf("OWNERSHIP_ABA_RESULT case=%s recovery_error=%v resulting_stage=%s foreign_present=%t\n",
			selected, removeErr, nativeTUNResource(&r.Native, 4, kind).Stage, len(after) != 0)
		if !bytes.Equal(original, after) {
			t.Errorf("OWNERSHIP_INVARIANT=FAIL: actual %s foreign replacement was deleted; durable receipt and fresh shape observation did not authenticate its lifetime", kind)
		}
		return nil
	})
	if err != nil {
		t.Fatal("reproduction setup or execution failed:", err)
	}
}

// Separate process with no journal writer or recovery code. Literal iproute2
// requests perform deletion, independently witness absence, then add the exact
// replacement. All resources are synthetic and contained in the child netns.
func TestNativeOwnershipABAReplacementHelper(t *testing.T) {
	kind := os.Getenv("SC_TEST_NATIVE_OWNERSHIP_ABA_REPLACER")
	if os.Getenv(ownershipABAOptIn) != "isolated-netns" || (kind != "rule" && kind != "route") {
		t.Skip("NOT_RUN: independent replacement subprocess only")
	}
	requireNativeQANetworkNamespace(t)
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != os.Getenv("SC_TEST_NATIVE_OWNERSHIP_ABA_NAMESPACE") {
		t.Fatal("replacement namespace identity changed")
	}
	before := ownershipABAObject(t, kind)
	if len(before) == 0 {
		t.Fatal("original object is absent")
	}
	args := func(verb string) []string {
		if kind == "rule" {
			return []string{"-4", "rule", verb, "priority", "10400", "fwmark", "0x530000/0xff0000", "table", "42424", "protocol", "247"}
		}
		return []string{"-4", "route", verb, "default", "dev", "sctunv70", "table", "42424", "metric", "100", "protocol", "247", "scope", "link", "src", "172.31.99.1"}
	}
	ingressNativeCommand(t, "/usr/sbin/ip", args("del")...)
	if len(ownershipABAObject(t, kind)) != 0 {
		t.Fatal("original object deletion was not independently witnessed")
	}
	fmt.Printf("OWNERSHIP_ABA_HELPER_ORIGINAL_ABSENT kind=%s pid=%d\n", kind, os.Getpid())
	ingressNativeCommand(t, "/usr/sbin/ip", args("add")...)
	after := ownershipABAObject(t, kind)
	if !bytes.Equal(before, after) {
		t.Fatalf("new foreign object differs: before=%s after=%s", before, after)
	}
	fmt.Printf("OWNERSHIP_ABA_HELPER_NEW_OBJECT kind=%s pid=%d shape=%s\n", kind, os.Getpid(), after)
}

// This reader does not call the product's canonicalization or matcher.
func ownershipABAObject(t *testing.T, kind string) []byte {
	t.Helper()
	args := []string{"-4", "-N", "-j", "route", "show", "table", "all"}
	if kind == "rule" {
		args = []string{"-4", "-N", "-j", "rule", "show"}
	}
	raw := ingressNativeCommand(t, "/usr/sbin/ip", args...)
	var rows []map[string]any
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		t.Fatal(err)
	}
	var found []byte
	for _, row := range rows {
		matches := fmt.Sprint(row["table"]) == "42424" && fmt.Sprint(row["metric"]) == "100"
		if kind == "rule" {
			matches = fmt.Sprint(row["priority"]) == "10400"
		}
		if !matches {
			continue
		}
		if found != nil {
			t.Fatal("independent reader found duplicate target objects")
		}
		var err error
		found, err = json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
	}
	return found
}

func ownershipABADisjoint(t *testing.T) string {
	t.Helper()
	return ingressNativeCommand(t, "/usr/sbin/ip", "-4", "-N", "-j", "route", "show", "table", "29999") +
		ingressNativeCommand(t, "/usr/sbin/ip", "-4", "-N", "-j", "rule", "show", "priority", "20000")
}
