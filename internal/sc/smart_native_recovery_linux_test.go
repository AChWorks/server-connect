//go:build linux

package sc

import (
	"context"
	"encoding/json"
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
	rules           map[string][]string
	routes          map[string]string
	hasNft          bool
	foreignNft      bool
	hasDocker       bool
	dockerRules     map[string]bool
	dockerMalformed bool
	failOnce        string
	mutations       []string
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
		tables := "table inet unrelated-product\n"
		if r.hasNft {
			tables += "table inet sing-box\n"
		}
		if r.hasDocker {
			tables += "table ip filter\n"
		}
		return tables, nil
	case "nft -j -a list table ip filter":
		if !r.hasDocker {
			return "", fmt.Errorf("Docker filter table missing")
		}
		entries := []any{
			map[string]any{"metainfo": map[string]any{
				"version": "1.1.0", "release_name": "fixture", "json_schema_version": 1}},
			map[string]any{"table": map[string]any{"family": "ip", "name": "filter", "handle": 1}},
			map[string]any{"chain": map[string]any{"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 2}},
			map[string]any{"rule": map[string]any{"family": "ip", "table": "filter",
				"chain": "DOCKER-USER", "handle": 18,
				"expr": []any{map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}},
					map[string]any{"return": nil}}}},
		}
		for _, item := range []struct {
			key, comment string
			handle       int
		}{
			{"iifname", "!sing-box: Docker compatibility input from tun", 41},
			{"oifname", "!sing-box: Docker compatibility output to tun", 42},
		} {
			if !r.dockerRules[item.key] {
				continue
			}
			iface := "sctun0"
			if r.dockerMalformed && item.key == "iifname" {
				iface = "foreign0"
			}
			entries = append(entries, map[string]any{"rule": map[string]any{
				"family": "ip", "table": "filter", "chain": "DOCKER-USER",
				"handle": item.handle, "comment": item.comment,
				"expr": []any{map[string]any{"match": map[string]any{
					"left": map[string]any{"meta": map[string]any{"key": item.key}},
					"op":   "==", "right": iface}},
					map[string]any{"counter": map[string]any{"packets": 12, "bytes": 1388}},
					map[string]any{"accept": nil}},
			}})
		}
		document, err := json.Marshal(map[string]any{"nftables": entries})
		return string(document), err
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
	if binary == "nft" && len(args) == 7 && strings.Join(args[:6], " ") == "delete rule ip filter DOCKER-USER handle" && r.hasDocker {
		var expected string
		switch args[6] {
		case "41":
			expected = "iifname"
		case "42":
			expected = "oifname"
		}
		if expected != "" && r.dockerRules[expected] {
			r.dockerRules[expected] = false
			return nil
		}
	}
	if binary == "ip" && len(args) == 8 && args[1] == "route" && args[2] == "del" &&
		args[3] == "table" && args[4] == "3362254344" && args[5] == "local" &&
		args[7] == "dev" {
		return fmt.Errorf("incorrect fake route argument order")
	}
	if binary == "ip" && len(args) == 9 && args[1] == "route" && args[2] == "del" &&
		args[3] == "table" && args[4] == "3362254344" && args[5] == "local" &&
		args[7] == "dev" {
		family := args[0]
		host, dev := args[6], args[8]
		want := fmt.Sprintf("local %s dev %s scope host", host, dev)
		if family == "-6" {
			want = fmt.Sprintf("local %s dev %s metric 1024 pref medium", host, dev)
		}
		if !strings.Contains(r.routes[family], want+"\n") {
			return fmt.Errorf("unexpected fake route deletion: %s", key)
		}
		r.routes[family] = strings.Replace(r.routes[family], want+"\n", "", 1)
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

// This reproduces the separately authorized IRA-124 Debian12 field crash:
// official sing-box 1.14.3 on a host with Docker's default bridge leaves one
// additional local redirect in its private random table plus two tagged
// accept rules in Docker's foreign-owned DOCKER-USER chain.
func newNativeDockerCrashFixture() *nativeRecoveryRetryRunner {
	r := newNativeRecoveryRetryRunner()
	r.hasDocker = true
	r.dockerRules = map[string]bool{"iifname": true, "oifname": true}
	r.routes["-4"] += "local 127.0.0.1 dev docker0 scope host\n"
	return r
}

func TestNativeRecoveryDockerCrashPreservesForeignRules(t *testing.T) {
	r := newNativeDockerCrashFixture()
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	if err := recoverNativeRedirect(context.Background(), r, scope); err != nil {
		t.Fatalf("Docker-enabled Core SIGKILL recovery failed: %v", err)
	}
	if r.hasNft || r.routes["-4"] != "" || r.routes["-6"] != "" ||
		r.dockerRules["iifname"] || r.dockerRules["oifname"] {
		t.Fatalf("owned Core/Docker policy not restored: %+v", r)
	}
	if !r.hasDocker {
		t.Fatal("foreign Docker nft table was removed")
	}
	for _, action := range r.mutations {
		if action == "nft delete table ip filter" || strings.Contains(action, "40960") ||
			strings.Contains(action, "DOCKER-USER handle 18") || strings.Contains(action, "unrelated-product") {
			t.Fatalf("Docker or unrelated resource was modified: %s", action)
		}
	}
	for _, family := range []string{"-4", "-6"} {
		for _, line := range r.rules[family] {
			if strings.Contains(line, "1: from all") || strings.Contains(line, "1420") ||
				strings.Contains(line, "32768") {
				t.Fatalf("Core RPDB remains: %s", line)
			}
		}
	}
	// Both private Docker rules MUST disappear before the last priority-1
	// route-table identity is destroyed, so a partial cleanup is retryable.
	dockerFinal := -1
	firstIdentityDeletion := -1
	for i, action := range r.mutations {
		if strings.Contains(action, "nft delete rule ip filter DOCKER-USER handle") {
			dockerFinal = i
		}
		if strings.Contains(action, "rule del pref 1 table 3362254344") && firstIdentityDeletion == -1 {
			firstIdentityDeletion = i
		}
	}
	if dockerFinal == -1 || firstIdentityDeletion == -1 || dockerFinal >= firstIdentityDeletion {
		t.Fatalf("unsafe Docker-vs-identity deletion order: %v", r.mutations)
	}
	prior := len(r.mutations)
	if err := recoverNativeRedirect(context.Background(), r, scope); err != nil || len(r.mutations) != prior {
		t.Fatalf("clean Docker recovery must be idempotent: %v, actions=%v", err, r.mutations[prior:])
	}
}

func TestNativeRecoveryDockerInterruptedCleanupIsRetryable(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, fail := range []string{
		"ip -4 route del table 3362254344 local 127.0.0.1 dev docker0",
		"nft delete rule ip filter DOCKER-USER handle 42",
		"nft delete table inet sing-box",
		"ip -6 rule del pref 1 table 3362254344",
	} {
		t.Run(fail, func(t *testing.T) {
			r := newNativeDockerCrashFixture()
			r.failOnce = fail
			if err := recoverNativeRedirect(context.Background(), r, scope); err == nil {
				t.Fatal("injected crash recovery failure ignored")
			}
			if !strings.Contains(strings.Join(r.rules["-4"], "\n")+strings.Join(r.rules["-6"], "\n"),
				"1: from all lookup 3362254344") {
				t.Fatal("cleanup lost random-table owner identity before completion")
			}
			if err := recoverNativeRedirect(context.Background(), r, scope); err != nil {
				t.Fatalf("exact Docker crash retry failed: %v", err)
			}
			if r.hasNft || r.dockerRules["iifname"] || r.dockerRules["oifname"] ||
				r.routes["-4"] != "" || r.routes["-6"] != "" {
				t.Fatalf("retry stranded Core effects: %+v", r)
			}
		})
	}
}

func TestNativeRecoveryDockerForeignCollisionRefusedBeforeMutation(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	t.Run("unexpected-bridge", func(t *testing.T) {
		r := newNativeDockerCrashFixture()
		r.routes["-4"] += "local 127.0.0.1 dev br-foreign scope host\n"
		if err := recoverNativeRedirect(context.Background(), r, scope); err == nil || len(r.mutations) != 0 {
			t.Fatalf("foreign bridge route adopted: %v mutations=%v", err, r.mutations)
		}
	})
	t.Run("spoofed-docker-rule", func(t *testing.T) {
		r := newNativeDockerCrashFixture()
		r.dockerMalformed = true
		if err := recoverNativeRedirect(context.Background(), r, scope); err == nil || len(r.mutations) != 0 {
			t.Fatalf("foreign nft expression adopted: %v mutations=%v", err, r.mutations)
		}
	})
	t.Run("duplicate-local-route", func(t *testing.T) {
		r := newNativeDockerCrashFixture()
		r.routes["-4"] += "local 127.0.0.1 dev docker0 scope host\n"
		if err := recoverNativeRedirect(context.Background(), r, scope); err == nil || len(r.mutations) != 0 {
			t.Fatalf("duplicate loopback redirect adopted: %v mutations=%v", err, r.mutations)
		}
	})
	t.Run("orphan-without-random-table", func(t *testing.T) {
		r := newNativeDockerCrashFixture()
		r.rules["-4"] = []string{"0: from all lookup local", "32766: from all lookup main"}
		r.rules["-6"] = []string{"0: from all lookup local", "32766: from all lookup main"}
		r.routes["-4"], r.routes["-6"] = "", ""
		if err := recoverNativeRedirect(context.Background(), r, scope); err == nil || len(r.mutations) != 0 {
			t.Fatalf("unattributed Docker rules adopted: %v mutations=%v", err, r.mutations)
		}
	})
}

// Redacted exact nft JSON structure read from the authorized IRA-124
// post-SIGKILL evidence. No operator profiles or unrelated firewall rules
// are retained: only the Core's two injected rules and Docker's return rule.
const nativeIRADockerCrashNFT = `{"nftables":[{"metainfo":{"json_schema_version":1,"release_name":"Lester Gooch #5","version":"1.0.6"}},{"table":{"family":"ip","handle":3,"name":"filter"}},{"chain":{"family":"ip","handle":7,"name":"DOCKER-USER","table":"filter"}},{"rule":{"chain":"DOCKER-USER","comment":"!sing-box: Docker compatibility input from tun","expr":[{"match":{"left":{"meta":{"key":"iifname"}},"op":"==","right":"sctun0"}},{"counter":{"bytes":0,"packets":0}},{"accept":null}],"family":"ip","handle":42,"table":"filter"}},{"rule":{"chain":"DOCKER-USER","comment":"!sing-box: Docker compatibility output to tun","expr":[{"match":{"left":{"meta":{"key":"oifname"}},"op":"==","right":"sctun0"}},{"counter":{"bytes":0,"packets":0}},{"accept":null}],"family":"ip","handle":41,"table":"filter"}},{"rule":{"chain":"DOCKER-USER","expr":[{"counter":{"bytes":916,"packets":12}},{"return":null}],"family":"ip","handle":18,"table":"filter"}}]}`

func TestNativeDockerRecoveryParsesActualIRA124CoreRules(t *testing.T) {
	actions, err := nativeDockerRecoveryActions(nativeIRADockerCrashNFT, "sctun0")
	if err != nil {
		t.Fatalf("actual independently captured Core Docker rule layout refused: %v", err)
	}
	if len(actions) != 2 || strings.Join(actions[0].args, " ") !=
		"delete rule ip filter DOCKER-USER handle 42" ||
		strings.Join(actions[1].args, " ") !=
			"delete rule ip filter DOCKER-USER handle 41" {
		t.Fatalf("wrong exact Docker cleanup handles: %+v", actions)
	}
	if _, err := nativeDockerRecoveryActions(nativeIRADockerCrashNFT, "other-tun"); err == nil {
		t.Fatal("Core Docker rules from a different TUN must not be adopted")
	}
	if _, err := nativeDockerRecoveryActions(strings.Replace(nativeIRADockerCrashNFT,
		`"right":"sctun0"`, `"right":"foreign0"`, 1), "sctun0"); err == nil {
		t.Fatal("changed foreign Docker nft expression was accepted")
	}
}

// A leftover or spoofed native Docker compatibility accept rule must be
// rejected before a fresh Core can be armed, not adopted after a later crash.
type nativeDockerAdmissionRunner struct{ *nativeRecoveryRetryRunner }

func (r *nativeDockerAdmissionRunner) output(ctx context.Context, binary string, args ...string) (string, error) {
	key := binary + " " + strings.Join(args, " ")
	switch key {
	case "ip -o link show":
		return "1: lo: <LOOPBACK,UP> mtu 65536\n2: scouter0: <UP> mtu 1500\n", nil
	case "ip -o link show dev scouter0":
		return "2: scouter0: <UP> mtu 1500\n", nil
	}
	return r.nativeRecoveryRetryRunner.output(ctx, binary, args...)
}

func TestNativeAdmissionDockerRuleCannotBePreexisting(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprint("docker-core-rule-present=", present), func(t *testing.T) {
			r := newNativeRecoveryRetryRunner()
			r.hasNft = false
			r.hasDocker = true
			r.dockerRules = map[string]bool{"iifname": present, "oifname": present}
			r.rules["-4"] = []string{"0: from all lookup local", "32766: from all lookup main",
				"32767: from all lookup default"}
			r.rules["-6"] = []string{"0: from all lookup local", "32766: from all lookup main"}
			r.routes["-4"], r.routes["-6"] = "", ""
			wrapped := &nativeDockerAdmissionRunner{r}
			err := inspectNativeAdmission(context.Background(), wrapped, scope)
			if present && err == nil || !present && err != nil {
				t.Fatalf("unexpected admission for Docker rule presence %v: %v", present, err)
			}
			if len(r.mutations) != 0 {
				t.Fatalf("read-only admission mutated Docker resource: %v", r.mutations)
			}
		})
	}
}
