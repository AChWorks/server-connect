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

// Run only in the disconnected disposable installed-host guest against an
// exact staged post-Core-crash kernel layout. This exercises real ip/nft
// cleanup, not the Core process or a live VPN/production host.
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
	orphanTun       bool
	orphanRoute     bool
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
	case "ip -o link show":
		links := "1: lo: <LOOPBACK,UP> mtu 65536\n2: scouter0: <UP> mtu 1500\n"
		if r.orphanTun {
			links += "3: sctun0: <POINTOPOINT,UP> mtu 1380\n"
		}
		return links, nil
	case "ip -4 route show table all":
		if r.orphanRoute {
			return "local 127.0.0.1 dev scouter0 table 3362254344 scope host\n", nil
		}
		return "local 127.0.0.1 dev lo table local scope host\n", nil
	case "ip -6 route show table all":
		if r.orphanRoute {
			return "local ::1 dev scouter0 table 3362254344 metric 1024 pref medium\n", nil
		}
		return "local ::1 dev lo table local proto kernel metric 0 pref medium\n", nil
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

func TestNativeAdmissionReservesExactFallbackSlotAndAllTableReferences(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, tc := range []struct {
		name, rule string
	}{
		{"fallback-occupied-by-foreign-owner", "32768: from all lookup 999"},
		{"foreign-lookalike-at-30000", "30000: not from all fwmark 0x2024 lookup 27432"},
		{"foreign-table-reference-below-managed", "9000: from all lookup 27432"},
		{"foreign-table-reference-above-managed", "45000: from all lookup 27432"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newNativeRecoveryRetryRunner()
			r.hasNft = false
			r.routes["-4"], r.routes["-6"] = "", ""
			r.rules["-4"] = []string{"0: from all lookup local", "32766: from all lookup main",
				"32767: from all lookup default", "40960: from all lookup 123", tc.rule}
			r.rules["-6"] = []string{"0: from all lookup local", "32766: from all lookup main"}
			if err := inspectNativeAdmission(context.Background(), &nativeDockerAdmissionRunner{r}, scope); err == nil ||
				len(r.mutations) != 0 {
				t.Fatalf("reserved resource admitted on fresh Core start: %v / %v", err, r.mutations)
			}
		})
	}
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

// On the physical Debian 13 host the SIGKILL-ed official Core removed its
// randomized table identity, nft table and TUN, but LEFT fixed native RPDB
// rules 14200/14201/14202/32768 in both address families. The installed
// stop hook deliberately refused that unsupported orphan before mutation.
func newNativeCoreSIGKILLOrphanFixture() *nativeRecoveryRetryRunner {
	r := newNativeRecoveryRetryRunner()
	r.hasNft = false
	for _, family := range []string{"-4", "-6"} {
		var kept []string
		for _, line := range r.rules[family] {
			if !strings.HasPrefix(line, "1: ") {
				kept = append(kept, line)
			}
		}
		r.rules[family] = kept
		r.routes[family] = ""
	}
	return r
}

func TestNativeCoreSIGKILLWithoutRandomTableIdentityRequiresConsumedClaim(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	r := newNativeCoreSIGKILLOrphanFixture()
	if err := recoverNativeRedirect(context.Background(), r, scope); err == nil {
		t.Fatal("unclaimed orphan RPDB rules were implicitly adopted")
	}
	if len(r.mutations) != 0 {
		t.Fatalf("unclaimed cleanup mutated network: %v", r.mutations)
	}
	if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, true); err != nil {
		t.Fatalf("verified Core-start claim could not recover physical SIGKILL orphan: %v", err)
	}
	for _, family := range []string{"-4", "-6"} {
		text := strings.Join(r.rules[family], "\n")
		for _, leaked := range []string{"14200:", "14201:", "14202:", "32768:"} {
			if strings.Contains(text, leaked) {
				t.Fatalf("Core orphan rule remains %s in %s", leaked, family)
			}
		}
		if !strings.Contains(text, "40960: from all lookup 123") {
			t.Fatalf("foreign routing rule was lost in %s: %s", family, text)
		}
	}
	if len(r.mutations) != 8 {
		t.Fatalf("expected only four owned RPDB deletions per family, got %v", r.mutations)
	}
	before := len(r.mutations)
	if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, true); err != nil ||
		len(r.mutations) != before {
		t.Fatalf("exact orphan cleanup not idempotent: %v / %v", err, r.mutations[before:])
	}
}

func TestNativeCoreSIGKILLOrphanCleanupFailureIsExactlyRetryable(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	r := newNativeCoreSIGKILLOrphanFixture()
	r.failOnce = "ip -4 rule del pref 14201"
	if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, true); err == nil {
		t.Fatal("interrupted RPDB cleanup unexpectedly passed")
	}
	if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, true); err != nil {
		t.Fatalf("exact claimed retry failed: %v", err)
	}
	for _, family := range []string{"-4", "-6"} {
		text := strings.Join(r.rules[family], "\n")
		if strings.Contains(text, "1420") || strings.Contains(text, "32768:") ||
			!strings.Contains(text, "40960: from all lookup 123") {
			t.Fatalf("retry altered foreign rules or left managed rules: %s", text)
		}
	}
}

func TestNativeCoreSIGKILLOrphanRefusesEveryUnsupportedIdentity(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, tc := range []struct {
		name   string
		change func(*nativeRecoveryRetryRunner)
	}{
		{"unverified-start", func(r *nativeRecoveryRetryRunner) {}},
		{"still-present-core-nft", func(r *nativeRecoveryRetryRunner) { r.hasNft = true }},
		{"remaining-core-tunnel", func(r *nativeRecoveryRetryRunner) { r.orphanTun = true }},
		{"unattributed-redirect-route", func(r *nativeRecoveryRetryRunner) { r.orphanRoute = true }},
		{"foreign-managed-rule", func(r *nativeRecoveryRetryRunner) {
			r.rules["-4"] = append(r.rules["-4"], "14200: from all lookup 999")
		}},
		{"foreign-same-body-fallback-priority-30000", func(r *nativeRecoveryRetryRunner) {
			r.rules["-4"] = append(r.rules["-4"], "30000: not from all fwmark 0x2024 lookup 27432")
		}},
		{"foreign-reserved-reference-before-14200", func(r *nativeRecoveryRetryRunner) {
			r.rules["-6"] = append(r.rules["-6"], "9500: from all lookup 27432")
		}},
		{"foreign-reserved-reference-after-32768", func(r *nativeRecoveryRetryRunner) {
			r.rules["-4"] = append(r.rules["-4"], "40000: from all fwmark 0x2023 lookup 27432")
		}},
		{"foreign-reserved-reference-between-slots", func(r *nativeRecoveryRetryRunner) {
			r.rules["-6"] = append(r.rules["-6"], "20000: from all lookup 27432")
		}},
		{"foreign-fixed-fallback-body", func(r *nativeRecoveryRetryRunner) {
			for i, rule := range r.rules["-4"] {
				if strings.HasPrefix(rule, "32768:") {
					r.rules["-4"][i] = "32768: from all lookup 999"
				}
			}
		}},
		{"foreign-docker-injection", func(r *nativeRecoveryRetryRunner) {
			r.hasDocker = true
			r.dockerRules = map[string]bool{"iifname": true, "oifname": true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newNativeCoreSIGKILLOrphanFixture()
			tc.change(r)
			verified := tc.name != "unverified-start"
			if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, verified); err == nil {
				t.Fatalf("unsafe orphan case accepted: %s", tc.name)
			}
			if len(r.mutations) != 0 {
				t.Fatalf("unsafe orphan case mutated kernel: %s: %v", tc.name, r.mutations)
			}
		})
	}
}

// An interrupted cleanup may have already removed any proper subset of
// fixed-slot rules. Missing owned rules are not replaced with an arbitrary
// same-looking fallback: only still-present exact identities are retired.
func TestNativeCoreSIGKILLOrphanExactPartialSubsets(t *testing.T) {
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	for _, removed := range [][]string{
		{"14200:", "32768:"},
		{"14201:", "14202:", "32768:"},
		{"14200:", "14201:", "14202:", "32768:"},
	} {
		t.Run(strings.Join(removed, "-"), func(t *testing.T) {
			r := newNativeCoreSIGKILLOrphanFixture()
			for _, family := range []string{"-4", "-6"} {
				var keep []string
				for _, line := range r.rules[family] {
					owned := false
					for _, prefix := range removed {
						owned = owned || strings.HasPrefix(line, prefix)
					}
					if !owned {
						keep = append(keep, line)
					}
				}
				r.rules[family] = keep
			}
			if err := recoverNativeRedirectWithVerifiedOrphan(context.Background(), r, scope, true); err != nil {
				t.Fatalf("exact partial-owned subset refused: %v", err)
			}
			for _, family := range []string{"-4", "-6"} {
				got := strings.Join(r.rules[family], "\n")
				if strings.Contains(got, "1420") || strings.Contains(got, "32768:") ||
					!strings.Contains(got, "40960: from all lookup 123") {
					t.Fatalf("partial recovery modified foreign or retained Core rules: %s", got)
				}
			}
		})
	}
}

// Run only in an explicitly isolated, disposable Linux network namespace
// whose harness pre-staged the *exact* fixed-slot orphan RPDB layout after
// an already stopped Core. This exercises the actual iproute2 recovery calls,
// separate from the fake kernel and the physical installed crash test.
func TestNativeCoreSIGKILLOrphanRealKernelNamespace(t *testing.T) {
	if os.Getenv("SC_NATIVE_ORPHAN_GUEST") != "yes" {
		t.Skip("requires explicitly prepared disconnected orphan network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("real kernel orphan test requires root in isolated namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil || current == init {
		t.Fatal("refuse to mutate initial host namespace")
	}
	scope := nativeRedirectRecovery{TunnelIF: "sctun0", UnderlayIF: "scouter0",
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
	r := nativeSystemRunner{}
	ctx := context.Background()
	baseline4, err := r.output(ctx, "ip", "-4", "rule", "show")
	if err != nil {
		t.Fatal(err)
	}
	baseline6, err := r.output(ctx, "ip", "-6", "rule", "show")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(baseline4, "14200:") ||
		!strings.Contains(baseline6, "14200:") ||
		!strings.Contains(baseline4, "32768:") ||
		!strings.Contains(baseline6, "32768:") {
		t.Fatal("isolated kernel did not stage the intended Core-owned orphan RPDB rules")
	}
	// A foreign writer can insert a same-looking fallback at an unrelated
	// priority after our Core has crashed. The installed recovery must not
	// delete even one of the genuinely owned rules before refusing it.
	if err := r.run(ctx, "ip", "-4", "rule", "add", "pref", "30000",
		"not", "fwmark", "0x2024", "lookup", "27432"); err != nil {
		t.Fatalf("disposable foreign-priority fixture failed: %v", err)
	}
	withForeign4, err := r.output(ctx, "ip", "-4", "rule", "show")
	// iproute2 uses tabs between priority and body on real Debian kernels;
	// inspect the parsed rule identity rather than relying on whitespace.
	foreignPresent := false
	for _, line := range strings.Split(withForeign4, "\n") {
		parts := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
		if parts != nil && parts[1] == "30000" &&
			parts[2] == "not from all fwmark 0x2024 lookup 27432" {
			foreignPresent = true
		}
	}
	if err != nil || !foreignPresent {
		t.Fatalf("foreign-priority fixture not independently observed: %v %s", err, withForeign4)
	}
	if err := recoverNativeRedirectWithVerifiedOrphan(ctx, r, scope, true); err == nil {
		t.Fatal("real kernel adopted foreign 30000 fallback under a consumed claim")
	}
	unchangedForeign4, fe4 := r.output(ctx, "ip", "-4", "rule", "show")
	unchangedForeign6, fe6 := r.output(ctx, "ip", "-6", "rule", "show")
	if fe4 != nil || fe6 != nil || unchangedForeign4 != withForeign4 || unchangedForeign6 != baseline6 {
		t.Fatal("foreign-priority refusal changed real RPDB before mutation")
	}
	if err := r.run(ctx, "ip", "-4", "rule", "del", "pref", "30000"); err != nil {
		t.Fatalf("test-owned foreign RPDB fixture could not be retired: %v", err)
	}
	if restored4, e := r.output(ctx, "ip", "-4", "rule", "show"); e != nil || restored4 != baseline4 {
		t.Fatal("foreign-priority test setup did not restore exact baseline")
	}
	t.Log("QA_NATIVE_REAL_KERNEL_FOREIGN_PRIORITY_30000_NO_MUTATION=PASS")
	if err := recoverNativeRedirect(ctx, r, scope); err == nil {
		t.Fatal("strict unclaimed real kernel recovery adopted the orphan")
	}
	unchanged4, e4 := r.output(ctx, "ip", "-4", "rule", "show")
	unchanged6, e6 := r.output(ctx, "ip", "-6", "rule", "show")
	if e4 != nil || e6 != nil || unchanged4 != baseline4 || unchanged6 != baseline6 {
		t.Fatal("unclaimed real kernel refusal modified RPDB")
	}
	if err := recoverNativeRedirectWithVerifiedOrphan(ctx, r, scope, true); err != nil {
		t.Fatalf("owned Core orphan cleanup failed on real kernel: %v", err)
	}
	for _, family := range []string{"-4", "-6"} {
		raw, err := r.output(ctx, "ip", family, "rule", "show")
		if err != nil {
			t.Fatal(err)
		}
		for _, pref := range []string{"14200:", "14201:", "14202:", "32768:"} {
			if strings.Contains(raw, pref) {
				t.Fatalf("%s Core orphan RPDB rule remains in %s", pref, family)
			}
		}
	}
	if err := recoverNativeRedirectWithVerifiedOrphan(ctx, r, scope, true); err != nil {
		t.Fatalf("idempotent real kernel cleanup failed: %v", err)
	}
	t.Log("QA_NATIVE_REAL_KERNEL_CONSUMED_ORPHAN_RECOVERY=PASS")
}
