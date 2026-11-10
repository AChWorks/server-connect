//go:build linux

package sc

import (
	"context"
	"fmt"
	"os"
	"strconv"
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

// Simulate real kernel state changing after each privileged action. In
// particular, inject a failure at the nft deletion that used to strand a
// still-present sing-box table after both priority-1 identity rules vanished.
type nativeRecoveryRetryRunner struct {
	rules      map[string][]string
	routes     map[string]string
	hasNft     bool
	foreignNft bool
	failOnce   string
	mutations  []string
}

func newNativeRecoveryRetryRunner() *nativeRecoveryRetryRunner {
	return &nativeRecoveryRetryRunner{
		rules: map[string][]string{
			"-4": {"0: from all lookup local", "1: from all lookup 3362254344",
				"14200: from all fwmark 0x2024 goto 14202", "14201: from all fwmark 0x2023 lookup 27432",
				"14202: from all nop", "32766: from all lookup main", "32767: from all lookup default",
				"32768: not from all fwmark 0x2024 lookup 27432", "40960: from all lookup 123"},
			"-6": {"0: from all lookup local", "1: from all lookup 3362254344",
				"14200: from all fwmark 0x2024 goto 14202", "14201: from all fwmark 0x2023 lookup 27432",
				"14202: from all nop", "32766: from all lookup main", "32768: not from all fwmark 0x2024 lookup 27432",
				"40960: from all lookup 123"},
		},
		routes: map[string]string{
			"-4": "local 127.0.0.1 dev scouter0 scope host\n",
			"-6": "local ::1 dev scouter0 metric 1024 pref medium\n",
		},
		hasNft: true,
	}
}

func (r *nativeRecoveryRetryRunner) output(_ context.Context, binary string, args ...string) (string, error) {
	key := binary + " " + strings.Join(args, " ")
	switch key {
	case "ip -4 rule show":
		return strings.Join(r.rules["-4"], "\n") + "\n", nil
	case "ip -6 rule show":
		return strings.Join(r.rules["-6"], "\n") + "\n", nil
	case "ip -4 route show table 27432", "ip -6 route show table 27432":
		return "", nil
	case "ip -4 route show table 3362254344":
		return r.routes["-4"], nil
	case "ip -6 route show table 3362254344":
		return r.routes["-6"], nil
	case "nft list tables":
		if r.hasNft {
			return "table inet unrelated-product\ntable inet sing-box\n", nil
		}
		return "table inet unrelated-product\n", nil
	case "nft list table inet sing-box":
		if !r.hasNft {
			return "", fmt.Errorf("owned table absent")
		}
		body := "table inet sing-box {\n chain prerouting_prematch {\n iifname \"sctun0\" return\n }\n chain output_prematch {\n }\n}"
		if r.foreignNft {
			body += "\nchain foreign_extra {"
		}
		return body, nil
	default:
		return "", fmt.Errorf("unexpected native kernel inspection: %s", key)
	}
}

func (r *nativeRecoveryRetryRunner) run(_ context.Context, binary string, args ...string) error {
	key := binary + " " + strings.Join(args, " ")
	r.mutations = append(r.mutations, key)
	if key == r.failOnce {
		r.failOnce = ""
		return fmt.Errorf("injected interrupted native cleanup")
	}
	if key == "nft delete table inet sing-box" && r.hasNft {
		r.hasNft = false
		return nil
	}
	if binary == "ip" && len(args) >= 5 && args[1] == "route" && args[2] == "del" &&
		args[3] == "table" && args[4] == "3362254344" && r.routes[args[0]] != "" {
		r.routes[args[0]] = ""
		return nil
	}
	if binary == "ip" && len(args) >= 5 && args[1] == "rule" && args[2] == "del" && args[3] == "pref" {
		priority, err := strconv.Atoi(args[4])
		if err != nil {
			return err
		}
		if priority == 1 && (len(args) != 7 || args[5] != "table" || args[6] != "3362254344") {
			return fmt.Errorf("unverified priority-one identity")
		}
		family := args[0]
		for i, line := range r.rules[family] {
			if strings.HasPrefix(line, fmt.Sprintf("%d: ", priority)) {
				r.rules[family] = append(r.rules[family][:i:i], r.rules[family][i+1:]...)
				return nil
			}
		}
	}
	return fmt.Errorf("unexpected native kernel mutation: %s", key)
}

func TestNativeRecoveryNftFailureRetainsIdentityForExactRetry(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, failure := range []string{
		"nft delete table inet sing-box",
		"ip -6 rule del pref 1 table 3362254344",
	} {
		t.Run(failure, func(t *testing.T) {
			r := newNativeRecoveryRetryRunner()
			r.failOnce = failure
			if err := recoverNativeRedirect(context.Background(), r, scope); err == nil {
				t.Fatal("injected recovery failure was hidden")
			}
			// The same randomized table remains discoverable in at least one
			// priority-1 RPDB family; it is not inferred from the nft table name.
			if !strings.Contains(strings.Join(r.rules["-4"], "\n")+strings.Join(r.rules["-6"], "\n"),
				"1: from all lookup 3362254344") {
				t.Fatal("partial failure destroyed randomized redirect identity")
			}
			if err := recoverNativeRedirect(context.Background(), r, scope); err != nil {
				t.Fatalf("exact owned cleanup is not retryable: %v", err)
			}
			if r.hasNft || r.routes["-4"] != "" || r.routes["-6"] != "" {
				t.Fatalf("retry stranded owned nftables or routing: %+v", r)
			}
			for _, family := range []string{"-4", "-6"} {
				text := strings.Join(r.rules[family], "\n")
				if strings.Contains(text, "1: from all lookup 3362254344") ||
					strings.Contains(text, "14200:") || strings.Contains(text, "14201:") ||
					strings.Contains(text, "14202:") || strings.Contains(text, "32768:") ||
					!strings.Contains(text, "40960: from all lookup 123") {
					t.Fatalf("retry lost foreign rule or retained managed rules: %s", text)
				}
			}
			for _, action := range r.mutations {
				if strings.Contains(action, "unrelated-product") || strings.Contains(action, "40960") {
					t.Fatalf("cleanup modified foreign resource: %s", action)
				}
			}
			previous := len(r.mutations)
			if err := recoverNativeRedirect(context.Background(), r, scope); err != nil || len(r.mutations) != previous {
				t.Fatalf("clean retry not idempotent: err=%v new actions=%v", err, r.mutations[previous:])
			}
		})
	}
}

func TestNativeRecoveryForeignNftChainNeverMutates(t *testing.T) {
	r := newNativeRecoveryRetryRunner()
	r.foreignNft = true
	err := recoverNativeRedirect(context.Background(), r, nativeRedirectRecovery{
		TunnelIF: "sctun0", UnderlayIF: "scouter0", Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex,
	})
	if err == nil || len(r.mutations) != 0 || !r.hasNft {
		t.Fatalf("foreign nft chain was adopted: err=%v actions=%v", err, r.mutations)
	}
}
