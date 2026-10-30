package sc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This binary is compiled on the build host, then ONLY the exact opt-in test
// is run in the existing GitHub Actions --network none, systemd Docker guest.
// No namespace creation, hooks, packet routing or external network is needed.
// Every table/chain/rule below is an explicit, unhooked test-owned fixture.
func TestNativeNFTTableCAS(t *testing.T) {
	if os.Getenv("SC_TEST_NATIVE_NFT_CAS") != "disconnected-systemd" {
		t.Skip("NOT_RUN: native nft CAS requires explicit disconnected-systemd fixture")
	}
	if err := requireNativeNFTCASGuest(); err != nil {
		t.Fatal(err)
	}
	baseline, err := readNativeNFTTestRuleset()
	if err != nil || len(baseline) != 0 {
		t.Fatalf("native nft CAS requires proven empty initial ruleset: %v", err)
	}
	boot, err := trialBootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	kernel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		t.Fatal(err)
	}
	version, err := runNativeNFTTestCommand("", "--version")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("NATIVE_NFT_CAS_PLATFORM=kernel:%s nft:%s\n", strings.TrimSpace(string(kernel)), strings.TrimSpace(string(version)))

	t.Run("exact_generation", func(t *testing.T) {
		fixture := createNativeNFTTestTable(t, "")
		generation, before := fixture.stable(t)
		if err := nativeNFTDeleteTableCAS(before.handle, generation); err != nil {
			t.Fatal(err)
		}
		fixture.requireAbsent(t)
		fmt.Println("NATIVE_NFT_CAS_EXACT_DELETE=PASS")
	})
	t.Run("foreign_child_after_observation", func(t *testing.T) {
		fixture := createNativeNFTTestTable(t, "")
		generation, before := fixture.stable(t)
		fixture.addForeignChild(t)
		err := nativeNFTDeleteTableCAS(before.handle, generation)
		if !errors.Is(err, errNativeNFTGenerationChanged) || errors.Is(err, errNativeNFTOutcomeUnknown) {
			t.Fatalf("late foreign child did not produce verified stale rejection: %v", err)
		}
		fixture.requireUnchanged(t)
		fmt.Println("NATIVE_NFT_CAS_FOREIGN_CHILD=PASS")
	})
	t.Run("disjoint_change_and_reobserve", func(t *testing.T) {
		owned := createNativeNFTTestTable(t, "")
		generation, before := owned.stable(t)
		foreign := createNativeNFTTestTable(t, "")
		if err := nativeNFTDeleteTableCAS(before.handle, generation); !errors.Is(err, errNativeNFTGenerationChanged) {
			t.Fatalf("disjoint mutation did not reject stale transaction: %v", err)
		}
		owned.requireUnchanged(t)
		foreign.requireUnchanged(t)
		generation, before = owned.stable(t)
		if err := nativeNFTDeleteTableCAS(before.handle, generation); err != nil {
			t.Fatal(err)
		}
		owned.requireAbsent(t)
		foreign.requireUnchanged(t)
		fmt.Println("NATIVE_NFT_CAS_DISJOINT=PASS")
	})
	t.Run("same_name_replacement", func(t *testing.T) {
		original := createNativeNFTTestTable(t, "")
		generation, before := original.stable(t)
		if err := nativeNFTDeleteTableCAS(before.handle, generation); err != nil {
			t.Fatal(err)
		}
		original.requireAbsent(t)
		replacement := createNativeNFTTestTable(t, original.name)
		generation, after := replacement.stable(t)
		if before.handle == after.handle {
			t.Fatal("native table replacement reused the observed handle")
		}
		if err := nativeNFTDeleteTableCAS(before.handle, generation); !errors.Is(err, syscall.ENOENT) || errors.Is(err, errNativeNFTOutcomeUnknown) {
			t.Fatalf("old handle did not fail without deleting replacement: %v", err)
		}
		replacement.requireUnchanged(t)
		// The replacement's cleanup runs first. The old receipt never owns it.
		fmt.Println("NATIVE_NFT_CAS_REPLACEMENT=PASS")
	})
	t.Run("committed_but_ACK_lost", func(t *testing.T) {
		fixture := createNativeNFTTestTable(t, "")
		generation, before := fixture.stable(t)
		connection, err := openNativeNFTSocket()
		if err != nil {
			t.Fatal(err)
		}
		// Send the real bounded kernel batch, then suppress its reply at the
		// receive seam. No production fault knob or packet interception exists.
		err = nativeNFTDeleteTableUsing(nativeNFTLostTestReplies{connection}, connection.portID, before.handle, generation)
		_ = syscall.Close(connection.fd)
		if !errors.Is(err, errNativeNFTOutcomeUnknown) || !errors.Is(err, syscall.ETIMEDOUT) {
			t.Fatalf("lost ACK was reported as a known result: %v", err)
		}
		// Native absence proves the actual effect occurred; the transport API
		// nevertheless had to report uncertainty, not success or no effect.
		fixture.requireAbsent(t)
		fmt.Println("NATIVE_NFT_CAS_ACK_LOSS=PASS")
	})

	currentBoot, err := trialBootIdentity()
	if err != nil || currentBoot != boot {
		t.Fatalf("native fixture boot identity changed: %v", err)
	}
	after, err := readNativeNFTTestRuleset()
	if err != nil || len(after) != 0 {
		t.Fatalf("native nft CAS fixture left resources: %v", err)
	}
	if t.Failed() {
		return
	}
	fmt.Println("NATIVE_NFT_CAS_CLEANUP=PASS")
}

type nativeNFTLostTestReplies struct{ nativeNFTConnection }

func (nativeNFTLostTestReplies) receive() ([]byte, uint32, int, error) {
	return nil, 0, 0, syscall.ETIMEDOUT
}

func requireNativeNFTCASGuest() error {
	if err := trialDisposableContext(); err != nil {
		return err
	}
	hostname, err := os.Hostname()
	if err != nil || hostname != "sc-qa" {
		return errors.New("native nft CAS requires exact sc-qa hostname")
	}
	release, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(release), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = strings.Trim(pair[1], "\"")
		}
	}
	if fields["ID"] != "debian" || fields["VERSION_ID"] != "13" {
		return errors.New("native nft CAS requires Debian 13 fixture")
	}
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return err
	}
	pidOneNamespace, err := os.Stat("/proc/1/ns/net")
	if err != nil || !os.SameFile(self, pidOneNamespace) {
		return errors.New("native nft CAS requires guest PID1 network namespace")
	}
	if err := trialIsolatedNetwork(); err != nil {
		return err
	}
	// trialIsolatedNetwork checks the complete link + IPv4 route inventory.
	// IPv6 must independently contain only loopback routes as well.
	raw, err := nativeIPJSON("-j", "-6", "route", "show", "table", "all")
	if err != nil {
		return err
	}
	rows, err := selectiveRows(raw)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if selectiveText(row["dev"]) != "lo" {
			return errors.New("native nft CAS found non-loopback IPv6 routing")
		}
	}
	if err := verifyTrustedIPPath("/", nativeNFTPath, 0); err != nil {
		return err
	}
	return nil
}

func runNativeNFTTestCommand(script string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, nativeNFTPath, arguments...)
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	command.Dir = "/"
	command.WaitDelay = 250 * time.Millisecond
	command.Stdin = strings.NewReader(script)
	var output boundedFirewallOutput
	command.Stdout = &output
	command.Stderr = io.Discard
	err := command.Run()
	if err != nil {
		return nil, fmt.Errorf("native nft fixture command failed: %w", err)
	}
	return output.Bytes(), nil
}

func readNativeNFTTestRuleset() ([]map[string]any, error) {
	raw, err := runNativeNFTTestCommand("", "-j", "-a", "list", "ruleset")
	if err != nil {
		return nil, err
	}
	if _, err := decodeNFTSnapshot(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var envelope struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	return envelope.NFTables[1:], nil
}

type nativeNFTTestGraph struct {
	handle    uint64
	canonical []byte
	count     int
}

func observeNativeNFTTestTable(name string) (nativeNFTTestGraph, error) {
	rows, err := readNativeNFTTestRuleset()
	if err != nil {
		return nativeNFTTestGraph{}, err
	}
	var graph []map[string]any
	var handle uint64
	for _, row := range rows {
		for kind, value := range row {
			object, ok := value.(map[string]any)
			if !ok {
				return nativeNFTTestGraph{}, errors.New("native fixture object invalid")
			}
			if object["family"] != "inet" {
				continue
			}
			if kind == "table" && object["name"] == name {
				number, ok := object["handle"].(json.Number)
				if !ok || handle != 0 {
					return nativeNFTTestGraph{}, errors.New("native fixture table handle missing or duplicated")
				}
				handle, err = strconv.ParseUint(number.String(), 10, 64)
				if err != nil || handle == 0 {
					return nativeNFTTestGraph{}, errors.New("native fixture table handle invalid")
				}
				graph = append(graph, row)
			} else if object["table"] == name {
				graph = append(graph, row)
			}
		}
	}
	if handle == 0 && len(graph) != 0 {
		return nativeNFTTestGraph{}, errors.New("native fixture children lack their table")
	}
	if !normalizeNftVolatile(nativeNFTTestGraphValues(graph)) {
		return nativeNFTTestGraph{}, errors.New("native fixture counters unsupported")
	}
	canonical, err := json.Marshal(graph)
	return nativeNFTTestGraph{handle: handle, canonical: canonical, count: len(graph)}, err
}

func nativeNFTTestGraphValues(graph []map[string]any) []any {
	result := make([]any, len(graph))
	for i := range graph {
		result[i] = graph[i]
	}
	return result
}

type nativeNFTTestFixture struct {
	name     string
	observed nativeNFTTestGraph
}

func createNativeNFTTestTable(t *testing.T, name string) *nativeNFTTestFixture {
	t.Helper()
	if name == "" {
		var nonce [8]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			t.Fatal(err)
		}
		name = "sc_qacas_" + hex.EncodeToString(nonce[:])
	}
	fixture := &nativeNFTTestFixture{name: name}
	before, err := observeNativeNFTTestTable(name)
	if err != nil || before.handle != 0 {
		t.Fatalf("fixture name not proven absent: %v", err)
	}
	// Register before creation, including the failure-before-observed-receipt
	// path. That path preserves an unproven table and fails the fixture.
	t.Cleanup(func() { fixture.cleanup(t) })
	script := fmt.Sprintf("create table inet %s\nadd chain inet %s owned\nadd rule inet %s owned counter\n", name, name, name)
	if _, err := runNativeNFTTestCommand(script, "-f", "-"); err != nil {
		t.Fatal(err)
	}
	created, err := observeNativeNFTTestTable(name)
	if err != nil || created.handle == 0 || created.count != 3 {
		t.Fatalf("fixture creation receipt unavailable: %v", err)
	}
	fixture.observed = created
	return fixture
}

func (f *nativeNFTTestFixture) stable(t *testing.T) (uint32, nativeNFTTestGraph) {
	t.Helper()
	before, err := nativeNFTGeneration()
	if err != nil {
		t.Fatal(err)
	}
	current, err := observeNativeNFTTestTable(f.name)
	if err != nil {
		t.Fatal(err)
	}
	after, err := nativeNFTGeneration()
	if err != nil || before != after || before == 0 {
		t.Fatalf("fixture snapshot generation changed: %v", err)
	}
	if current.handle != f.observed.handle || !bytes.Equal(current.canonical, f.observed.canonical) {
		t.Fatal("fixture owned graph changed")
	}
	return before, current
}

func (f *nativeNFTTestFixture) requireUnchanged(t *testing.T) { t.Helper(); _, _ = f.stable(t) }

func (f *nativeNFTTestFixture) requireAbsent(t *testing.T) {
	t.Helper()
	current, err := observeNativeNFTTestTable(f.name)
	if err != nil || current.handle != 0 {
		t.Fatalf("fixture table is not proven absent: %v", err)
	}
}

func (f *nativeNFTTestFixture) addForeignChild(t *testing.T) {
	t.Helper()
	f.requireUnchanged(t)
	if _, err := runNativeNFTTestCommand(fmt.Sprintf("add chain inet %s foreign\n", f.name), "-f", "-"); err != nil {
		t.Fatal(err)
	}
	current, err := observeNativeNFTTestTable(f.name)
	if err != nil || current.handle != f.observed.handle || current.count != f.observed.count+1 {
		t.Fatalf("foreign child fixture creation uncertain: %v", err)
	}
	// This is a second explicit TEST owner, not authority for product cleanup.
	// The test knows both authored objects and removes them only after proof.
	f.observed = current
}

func (f *nativeNFTTestFixture) cleanup(t *testing.T) {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		generation, err := nativeNFTGeneration()
		if err != nil {
			t.Errorf("fixture cleanup generation unavailable: %v", err)
			return
		}
		current, err := observeNativeNFTTestTable(f.name)
		if err != nil {
			t.Errorf("fixture cleanup observation unavailable: %v", err)
			return
		}
		after, err := nativeNFTGeneration()
		if err != nil {
			t.Errorf("fixture cleanup generation unavailable: %v", err)
			return
		}
		if generation != after {
			continue
		}
		if current.handle == 0 {
			return
		}
		if f.observed.handle == 0 || current.handle != f.observed.handle || !bytes.Equal(current.canonical, f.observed.canonical) {
			t.Error("fixture cleanup preserves unproven or replaced table")
			return
		}
		err = nativeNFTDeleteTableCAS(current.handle, generation)
		if errors.Is(err, errNativeNFTGenerationChanged) {
			continue
		}
		observed, observationErr := observeNativeNFTTestTable(f.name)
		if observationErr == nil && observed.handle == 0 {
			return
		}
		t.Errorf("fixture cleanup not verified: delete=%v observation=%v", err, observationErr)
		return
	}
	t.Error("fixture cleanup could not obtain stable generation; preserving table")
}
