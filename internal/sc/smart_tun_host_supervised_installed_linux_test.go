//go:build linux

package sc

// This opt-in test is the sole installed routed initialization caller. It
// requires an independently resettable VM with an exact private attestation;
// it never authorizes general-host Connect, authenticates a release, or
// resolves native receipt ambiguity. Failure retains the production journal
// for the prearmed independent Recovery executor.
import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type hostSupervisorInstalledFixture struct {
	MachineID           string                   `json:"machine_id"`
	BootID              string                   `json:"boot_id"`
	RecoveryAttestation string                   `json:"recovery_attestation"`
	ManagementPeer      string                   `json:"management_peer"`
	UnderlayInterface   string                   `json:"underlay_interface"`
	TunnelInterface     string                   `json:"tunnel_interface"`
	EndpointIP          string                   `json:"endpoint_ip"`
	EndpointPort        int                      `json:"endpoint_port"`
	DNSResolver         string                   `json:"dns_resolver"`
	ExpectedDirectIP    string                   `json:"expected_direct_ip"`
	ExpectedVPNIP       string                   `json:"expected_vpn_ip"`
	Traces              [2]HostHealthTraceTarget `json:"traces"`
}

func readHostSupervisorInstalledFixture(t *testing.T) hostSupervisorInstalledFixture {
	t.Helper()
	if os.Getenv("SC_TEST_HOST_SUPERVISION_INSTALLED") != "disposable-resettable-kvm" {
		t.Skip("NOT_RUN: exact independently resettable installed KVM fixture required")
	}
	path := os.Getenv("SC_TEST_HOST_SUPERVISION_FIXTURE")
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		t.Fatal("installed host supervision requires root and an absolute exact fixture path")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != 0 || stat.Nlink != 1 || info.Size() > 16384 {
		t.Fatal("fixture must be a private root-owned regular 0600 file with one link")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 16385))
	if err != nil || len(raw) > 16384 || rejectAmbiguousJournalJSON(raw) != nil {
		t.Fatal("invalid installed fixture JSON")
	}
	var fixture hostSupervisorInstalledFixture
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fixture) != nil {
		t.Fatal("unsupported installed fixture schema")
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		t.Fatal("trailing installed fixture data")
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	boot, err := trialBootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if !journalHex32.MatchString(fixture.MachineID) || strings.TrimSpace(string(machine)) != fixture.MachineID ||
		fixture.BootID != boot || fixture.RecoveryAttestation != "independent-console-and-reset-verified" {
		t.Fatal("fixture host/boot or independent recovery attestation does not match")
	}
	vendor, err := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	if err != nil || strings.TrimSpace(string(vendor)) != "QEMU" {
		t.Fatal("fixture must be the explicitly resettable QEMU/KVM guest")
	}
	return fixture
}

func TestHostSupervisorInstalledBegin(t *testing.T) {
	fixture := readHostSupervisorInstalledFixture(t)
	m := New(DefaultDir, DefaultCore, DefaultPort)
	var expected hostCoreQAAdmission
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if _, _, err := store.readJournal(); !errors.Is(err, os.ErrNotExist) {
			return Fault("activation_journal_conflict", "installed fixture must start without a journal")
		}
		var err error
		expected, err = hostCoreQASelectedProfile(m, store, fixture.EndpointIP, fixture.ManagementPeer,
			fixture.UnderlayInterface, fixture.TunnelInterface, fixture.DNSResolver, 180)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// The exact installed no-journal dispatcher is exercised before arming.
	absent, err := m.RunSmartTUNHealthRound("")
	if err != nil || absent.Phase != "absent" || absent.RecoveryVerified || absent.GuardScheduled {
		t.Fatalf("absent dispatcher claimed routing state: %v %+v", err, absent)
	}
	roles, err := m.prearmHostRouteSupervisor()
	if err != nil {
		t.Fatal(err)
	}
	published := false
	var operation, challenge string
	err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		actual, err := hostCoreQASelectedProfile(m, store, fixture.EndpointIP, fixture.ManagementPeer,
			fixture.UnderlayInterface, fixture.TunnelInterface, fixture.DNSResolver, 180)
		if err != nil {
			return err
		}
		if !sameHostNativePrerequisites(expected.Native, actual.Native) || !reflect.DeepEqual(expected.Profile, actual.Profile) || !bytes.Equal(expected.Policy, actual.Policy) {
			return Fault("trial_observation_uncertain", "installed prerequisites changed during independent prearm")
		}
		path, err := observeGeneralHostSSHPath(fixture.ManagementPeer, fixture.UnderlayInterface)
		if err != nil {
			return err
		}
		plan := HostHealthPlan{Round: 1, OperationID: actual.Native.Progress.Ingress.OperationID,
			BootID: actual.Native.Progress.Ingress.BootID, ConfigSHA256: sha256Hex(actual.Policy),
			TunnelInterface: fixture.TunnelInterface, UnderlayInterface: fixture.UnderlayInterface,
			EndpointIP: fixture.EndpointIP, EndpointPort: fixture.EndpointPort,
			IPv4: HostHealthFamilyPlan{Enabled: true, UnderlaySource: path.Local.String(), DNSResolver: fixture.DNSResolver,
				ExpectedDirectIP: fixture.ExpectedDirectIP, ExpectedVPNIP: fixture.ExpectedVPNIP}}
		plans := [2]HostHealthPlan{plan, plan}
		for i := range plans {
			plans[i].IPv4.Trace = fixture.Traces[i]
		}
		options := SmartTUNHealthOptions{IntervalSeconds: 5, FailureThreshold: 2, MaxAttempts: 2, RecoverySeconds: 45}
		r, err := m.initializeHostRouteSupervisorLocked(store, actual, fixture.ManagementPeer, plans, options, roles)
		if err != nil {
			return err
		}
		published, operation = true, r.Progress.Ingress.OperationID
		if err := runHostCaptureGateLocked(store, &r.Progress, trialGuardScheduled, hostRouteCapturePersist(store, &r)); err != nil {
			return err
		}
		native := r.nativeView()
		if err := nativeTUNPrepareLinkWithPersist(store, &native, "", hostRouteNativePersist(store, &r)); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_possible"); err != nil {
			return err
		}
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, actual.Policy, nil); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "credential_staged"); err != nil {
			return err
		}
		watch, err := nativeTUNWatchStart(r.nativeView())
		if err != nil {
			return err
		}
		defer watch.close()
		if err := hostRouteCoreStagePersist(store, &r, "start_requested"); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		err = hostRouteCoreCommand(ctx, store, "start")
		cancel()
		if err != nil {
			return err
		}
		if err := watch.verify(r.nativeView()); err != nil {
			return err
		}
		if err := hostRouteCoreStagePersist(store, &r, "active_observed"); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "effect_possible"); err != nil {
			return err
		}
		native = r.nativeView()
		if err := nativeTUNApplyGuardFirstWithObserver(store, &native, "", hostRouteNativePersist(store, &r), hostRouteNFTObserver(&r)); err != nil {
			return err
		}
		if err := hostRoutePhasePersist(store, &r, "observed"); err != nil {
			return err
		}
		challenge, err = readyHostRouteSupervisorLocked(store, &r)
		return err
	})
	if err != nil {
		if !published {
			m.disarmUncommittedSmartTUNHealth(roles)
			m.disarmUncommittedSmartTUNGuard()
		}
		t.Fatalf("installed supervised initialization failed; retained operation=%s: %v", operation, err)
	}
	// This challenge is private test output, not a repository artifact. Fresh
	// SSH confirmation is deliberately performed by the independent operator.
	receipt, _ := json.Marshal(map[string]string{"operation_id": operation, "challenge": challenge})
	fmt.Printf("HOST_SUPERVISION_PENDING_CONFIRMATION=%s\n", receipt)
	health, err := m.RunSmartTUNHealthRound("")
	if err != nil || health.OperationID != operation {
		t.Fatalf("installed Health dispatch failed: %v %+v", err, health)
	}
	recovery, err := m.RecoverGuardedRuleTrial("", "")
	if err != nil || recovery.OperationID != operation || recovery.RecoveryVerified || !recovery.GuardScheduled {
		t.Fatalf("independent activation guard did not preserve a live bounded lease: %v %+v", err, recovery)
	}
	status, err := m.InspectHostRouteSupervision()
	if err != nil || status.OperationID != operation || status.Phase != "host_route_awaiting_confirmation" ||
		status.GeneralHostAdmitted || status.Confirmed || status.RecoveryVerified {
		t.Fatalf("installed readiness/confirmation boundary false: %v %+v", err, status)
	}
	t.Log("PASS: real typed initialization, installed Health/Recovery dispatch; fresh SSH confirmation and fault/reboot acceptance remain external")
}
