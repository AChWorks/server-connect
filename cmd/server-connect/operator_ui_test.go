package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestOperatorMenuIsReadOnlyOnFirstUseAndHidesLegacyUntilAdvanced(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "not-installed"), "", 0)
	var out bytes.Buffer
	p := operatorPresenter{out: &out, width: 42}
	p.menu(m, false)
	basic := out.String()
	for _, want := range []string{"Server Connect", "0.1.0-dev", "State: not inspected", "NOT RELEASE-READY", "18 Mode Overview", "19 Routing Rules", "21 Smart Routing (guarded QA)", "22 Native Guard / Recovery Status", "a Toggle advanced", "0 Exit", "Choice:"} {
		if !strings.Contains(basic, want) {
			t.Fatalf("missing operator guidance %q in %s", want, basic)
		}
	}
	if strings.Contains(basic, "Selective Plan") || strings.Contains(basic, "Guarded Smart TUN (isolated") {
		t.Fatal("legacy/QA actions exposed as ordinary operator controls")
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("opening first-use menu created manager state")
	}
	out.Reset()
	p.menu(m, true)
	advanced := out.String()
	for _, want := range []string{"Advanced diagnostics", "11 Path Diagnostics"} {
		if !strings.Contains(advanced, want) {
			t.Fatalf("advanced tool unavailable: %q", want)
		}
	}
	if strings.Contains(advanced, "20 Guarded Smart TUN") {
		t.Fatal("obsolete isolated VM trial still appears in the advanced operator menu")
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("opening advanced menu created manager state")
	}
}

func TestStableVersionMenuHasNoDevelopmentQADisclaimer(t *testing.T) {
	previous := managerVersion
	managerVersion = "0.1.0"
	defer func() { managerVersion = previous }()
	m := sc.New(filepath.Join(t.TempDir(), "uninitialized"), "", 0)
	for _, width := range []int{42, 78} {
		var out bytes.Buffer
		p := operatorPresenter{out: &out, width: width}
		p.menu(m, false)
		text := out.String()
		for _, expected := range []string{"Server Connect  0.1.0", "21 Smart Routing (guarded)",
			"initial activation requires fresh SSH confirmation", "7 Disconnect / Return to Direct"} {
			if !strings.Contains(text, expected) {
				t.Fatalf("stable menu width %d missing %q: %s", width, expected, text)
			}
		}
		if strings.Contains(text, "guarded QA") || strings.Contains(text, "NOT RELEASE-READY") {
			t.Fatalf("stable build still advertises development-only mode: %s", text)
		}
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("stable first-use menu created private state")
	}
}

func TestOperatorPresenterNoANSIForPipesAndRedirects(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("COLUMNS", "40")
	for _, tc := range []struct {
		name string
		open func() (*os.File, func())
	}{
		{"pipe", func() (*os.File, func()) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			return w, func() { w.Close(); r.Close() }
		}},
		{"redirect-to-devnull", func() (*os.File, func()) {
			f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			return f, func() { f.Close() }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, close := tc.open()
			defer close()
			p := terminalPresenter(out)
			if p.color || p.tint("safe", "1;31") != "safe" || p.width != 40 {
				t.Fatal("nonterminal or narrow output was incorrectly decorated")
			}
		})
	}
	// Environment overrides ANSI even on an actual TTY. Color activation is
	// independently checked using a PTY smoke test, not a fragile fake TTY.
	t.Setenv("NO_COLOR", "")
	if terminalPresenter(os.Stdout).color {
		t.Fatal("NO_COLOR was ignored")
	}
}

func TestOperatorMenuProfileRemovalAndIncompleteInputNeverMutate(t *testing.T) {
	for _, input := range []string{
		"8\n", "8\n\n0\n", "8\ncancel\n0\n", "8\n0123456789abcdef\nNO\n0\n",
		"3\n", "3\nback\n0\n", "4\n", "6\nhttps://example.org\n3\n0\n",
	} {
		t.Run(strings.ReplaceAll(input, "\n", "_"), func(t *testing.T) {
			m := sc.New(filepath.Join(t.TempDir(), "no-state"), "", 0)
			in, wr, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(wr, input); err != nil {
				t.Fatal(err)
			}
			wr.Close()
			old := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = old; in.Close() }()
			code, _, _ := hostDriftCapturedOutput(t, func() int { return menu(m) })
			if code != 0 {
				t.Fatalf("cancel path terminated abnormally: %d", code)
			}
			if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
				t.Fatal("canceled/invalid input wrote private state")
			}
		})
	}
}

func TestOperatorErrorGuidanceHasConsequenceAndNextAction(t *testing.T) {
	for _, code := range []string{"guard_pending", "unsupported_host", "service_conflict", "invalid_arguments", "routing_rules_conflict", "routing_rules_hash_mismatch", "routing_rules_missing", "apt_policy_conflict", "apt_untrusted_executable", "proxy_unavailable", "operation_failed"} {
		state, next := operatorErrorGuidance(code)
		if state == "" || next == "" || !(strings.Contains(next, "server-connect") || strings.Contains(next, "sha256sum")) {
			t.Fatalf("guidance for %s lacks state or next action: %q / %q", code, state, next)
		}
		var buf bytes.Buffer
		operatorPrintError(&buf, sc.Fault(code, "safe operational failure"))
		if !strings.Contains(buf.String(), "Error ["+code+"]") || !strings.Contains(buf.String(), "State: ") || !strings.Contains(buf.String(), "Next: ") {
			t.Fatalf("error missing structured operator advice: %q", buf.String())
		}
	}
}

func TestOperatorPromptRequiresCompleteInput(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
		ok    bool
	}{
		{"profileid\n", "profileid", true},
		{"profileid", "", false},
		{"\n", "", false},
		{"back\n", "", false},
		{"cancel\n", "", false},
	} {
		answer, ok := operatorPrompt(bufio.NewReader(strings.NewReader(tc.input)), "ID: ", false)
		if answer != tc.want || ok != tc.ok {
			t.Fatalf("prompt accepted incomplete/canceled input %q: %q %v", tc.input, answer, ok)
		}
	}
}

// The obsolete isolated VM Apply menu must no longer expose a second
// operator workflow alongside native connect-smart. Unknown choice 20 is
// inert and cannot initialize private state or dispatch any privileged action.
func TestRetiredVMMenuIsInert(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "uninitialized-state"), "", 0)
	in, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(wr, "20\n0\n"); err != nil {
		t.Fatal(err)
	}
	_ = wr.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old; _ = in.Close() }()
	called := false
	code, out, stderr := hostDriftCapturedOutput(t, func() int {
		return menuWithRunner(m, func(*sc.Manager, ...string) int {
			called = true
			return 0
		})
	})
	if code != 0 || called || stderr != "" || !strings.Contains(out, "Unknown option") {
		t.Fatalf("retired VM menu dispatched an action or failed: code=%d called=%v stdout=%s stderr=%s", code, called, out, stderr)
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("retired VM option initialized manager state")
	}
}

func TestOperatorMenuConfirmedProfileRemovalUsesExistingManager(t *testing.T) {
	const id = "0123456789abcdef"
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	profiles := filepath.Join(stateDir, "profiles")
	if err := os.Mkdir(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	profile, err := json.Marshal(sc.Profile{
		ID: id, Name: "ephemeral-test-profile", Kind: "vless-link",
		Outbound: json.RawMessage(`{"type":"vless","server":"example.invalid"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(profiles, id+".json")
	if err := os.WriteFile(profilePath, profile, 0600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "state.json")
	if err := os.WriteFile(statePath, []byte(`{"version":1,"desired":"direct","selected":"`+id+`","port":20807}`), 0600); err != nil {
		t.Fatal(err)
	}
	m := sc.New(stateDir, "", 0)
	in, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(writer, "8\n"+id+"\nREMOVE\n0\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old; in.Close() }()
	code, out, stderr := hostDriftCapturedOutput(t, func() int { return menu(m) })
	if code != 0 || stderr != "" || !strings.Contains(out, "Completed:") {
		t.Fatalf("confirmed removal failed: code=%d out=%s stderr=%s", code, out, stderr)
	}
	if _, err := os.Lstat(profilePath); !os.IsNotExist(err) {
		t.Fatalf("confirmed removal retained the saved profile: %v", err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var stored sc.State
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Selected != "" || stored.Desired != "direct" || stored.Port != sc.DefaultPort {
		t.Fatalf("confirmed removal changed unrelated operator state: %+v", stored)
	}
}

// Capturing dispatch through the same menu path proves that no command is
// launched on cancellation. Valid diagnostic selections are checked without
// opening real sockets or touching privileged host state.
func TestOperatorAdvancedMenuRequiresCompleteExplicitInputs(t *testing.T) {
	const one = "https://one.example.test/"
	const two = "https://two.example.test/"
	const base = "11\n" + one + "\n" + two + "\n\n"
	many := []string{one, two, "https://three.example.test/", "https://four.example.test/", "https://five.example.test/"}
	manyInput := "11\n" + strings.Join(many, "\n") + "\n\n"
	manyCommand := "diagnose-path --via direct"
	for _, url := range many {
		manyCommand += " --url " + url
	}
	const endpoint = "198.51.100.17"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name, input, want string
	}{
		{"diagnose-back", base + "back\n0\n", ""},
		{"diagnose-cancel", base + "cancel\n0\n", ""},
		{"diagnose-empty-path", base + "\n0\n", ""},
		{"diagnose-invalid-choice", base + "3\n0\n", ""},
		{"diagnose-nonnumeric-choice", base + "proxy\n0\n", ""},
		{"diagnose-incomplete-path-eof", base + "1", ""},
		{"diagnose-first-blank", "11\n\n0\n", ""},
		{"diagnose-first-cancel", "11\ncancel\n0\n", ""},
		{"diagnose-additional-cancel", "11\n" + one + "\ncancel\n0\n", ""},
		{"diagnose-additional-back", "11\n" + one + "\nback\n0\n", ""},
		{"diagnose-additional-incomplete-eof", "11\n" + one + "\n", ""},
		{"diagnose-first-incomplete-eof", "11\n" + one, ""},
		{"diagnose-valid-one-direct", "11\n" + one + "\n\n2\n0\n", "diagnose-path --via direct --url " + one},
		{"diagnose-valid-proxy", base + "1\n0\n", "diagnose-path --via proxy --url " + one + " --url " + two},
		{"diagnose-valid-direct", base + "2\n0\n", "diagnose-path --via direct --url " + one + " --url " + two},
		{"diagnose-valid-five-direct", manyInput + "2\n0\n", manyCommand},
		{"retired-selective-menu", "12\n0\n", ""},
		{"retired-vm-trial-menu", "20\n0\n", ""},
		{"dns-back-last", "14\nnode.example.test\n" + endpoint + "\nback\n0\n", ""},
		{"dns-cancel-first", "14\ncancel\n0\n", ""},
		{"dns-eof-middle", "14\nnode.example.test\n" + endpoint, ""},
		{"dns-valid", "14\nnode.example.test\n" + endpoint + "\n203.0.113.53\n0\n", "underlay-dns --hostname node.example.test --endpoint " + endpoint + " --resolver 203.0.113.53"},
		{"tcp-optional-hostname-cancel", "13\n" + endpoint + "\n443\ncancel\n0\n", ""},
		{"tcp-optional-hostname-blank", "13\n" + endpoint + "\n443\n\n0\n", "underlay-tcp --endpoint " + endpoint + " --port 443"},
		{"host-drift-back", "15\nback\n0\n", ""},
		{"rules-via-cancel", "19\n2\n1.1.1.0/24\ncancel\n0\n", ""},
		{"rules-via-invalid", "19\n2\n1.1.1.0/24\nother\n0\n", ""},
		{"rules-suffix-back", "19\n3\nexample.org\nback\n0\n", ""},
		{"rules-suffix-invalid", "19\n3\nexample.org\nmaybe\n0\n", ""},
		{"rules-suffix-valid-no", "19\n3\nexample.org\nn\n0\n", "smart-routing-rules add --domain example.org --via vpn"},
		{"rules-suffix-valid-blank", "19\n3\nexample.org\n\n0\n", "smart-routing-rules add --domain example.org --via vpn"},
		{"rules-import-cancel-revision", "19\n4\n/tmp/rules.txt\nsource\n2026-01-01\n" + digest + "\ncancel\n0\n", ""},
		{"rules-import-blank-revision", "19\n4\n/tmp/rules.txt\nsource\n2026-01-01\n" + digest + "\n\n0\n", "smart-routing-rules import --file /tmp/rules.txt --source source --as-of 2026-01-01 --sha256 " + digest},
		{"rules-remove-source-eof", "19\n7\nsource\n" + digest, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := sc.New(filepath.Join(t.TempDir(), "uninitialized-state"), "", 0)
			in, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(writer, tc.input); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			old := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = old; _ = in.Close() }()
			var calls []string
			code, out, stderr := hostDriftCapturedOutput(t, func() int {
				return menuWithRunner(m, func(_ *sc.Manager, args ...string) int {
					calls = append(calls, strings.Join(args, " "))
					return 0
				})
			})
			if code != 0 || stderr != "" {
				t.Fatalf("menu failed: code=%d stderr=%s stdout=%s", code, stderr, out)
			}
			if tc.want == "" {
				if len(calls) != 0 {
					t.Fatalf("cancellation/invalid input dispatched commands: %q", calls)
				}
			} else if len(calls) != 1 || calls[0] != tc.want {
				t.Fatalf("explicit selection command mismatch: got %q, want %q; stdout=%s", calls, tc.want, out)
			}
			if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
				t.Fatalf("menu created state without a real operation: %v", err)
			}
		})
	}
}

// The real CLI validator must reject the entire menu-supplied set before
// sending even the first request. A successful local Direct diagnostic remains
// read-only and never grants VPN health or activation proof.
func TestOperatorPathDiagnosticsMenuSharesValidationAndRedactsTargets(t *testing.T) {
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	privateURL := server.URL + "/private/report?token=menu-secret"
	cases := []struct {
		name, input string
		wantProbes  int32
		wantError   bool
	}{
		{"one-valid", "11\n" + privateURL + "\n\n2\n0\n", 1, false},
		{"duplicate-host", "11\n" + privateURL + "\n" + server.URL + "/different-path\n\n2\n0\n", 0, true},
		{"credential-url", "11\n" + privateURL + "\nhttps://user:pass@other.example.test/private\n\n2\n0\n", 0, true},
		{"invalid-scheme", "11\n" + privateURL + "\nfile:///tmp/private\n\n2\n0\n", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probes.Store(0)
			m := sc.New(filepath.Join(t.TempDir(), "uninitialized-state"), "", 0)
			in, wr, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(wr, tc.input); err != nil {
				t.Fatal(err)
			}
			if err := wr.Close(); err != nil {
				t.Fatal(err)
			}
			old := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = old; in.Close() }()
			code, out, stderr := hostDriftCapturedOutput(t, func() int {
				return menuWithRunner(m, func(m *sc.Manager, args ...string) int {
					return run(true, m, args)
				})
			})
			if code != 0 || stderr != "" {
				t.Fatalf("menu failed: code=%d stderr=%q", code, stderr)
			}
			if tc.wantError && (!strings.Contains(out, `"ok":false`) || !strings.Contains(out, `"code":"invalid_arguments"`)) {
				t.Fatalf("invalid targets not rejected by CLI: %s", out)
			}
			if !tc.wantError && (!strings.Contains(out, `"ok":true`) || !strings.Contains(out, `"all_targets_reachable"`)) {
				t.Fatalf("valid one-target diagnosis not completed: %s", out)
			}
			for _, want := range []string{`"host_network_read_only":true`, `"tunnel_health_verified":false`, `"activation_ready":false`, `"fallback_attempted":false`} {
				if !strings.Contains(out, want) {
					t.Fatalf("diagnostic lost safe classification %s: %s", want, out)
				}
			}
			for _, secret := range []string{"menu-secret", "/private/report", "user:pass", "different-path"} {
				if strings.Contains(out, secret) || strings.Contains(stderr, secret) {
					t.Fatal("private diagnostic URL or credentials leaked to menu output")
				}
			}
			if got := probes.Load(); got != tc.wantProbes {
				t.Fatalf("probe count %d, want %d (invalid input must not probe)", got, tc.wantProbes)
			}
			if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
				t.Fatal("read-only diagnostic initialized product state")
			}
		})
	}
}

func TestOperatorMenuNativeModeTruthfulAcrossHealthAndRecovery(t *testing.T) {
	p := operatorPresenter{out: io.Discard, width: 78}
	const selected = "0123456789abcdef"
	cases := []struct {
		name           string
		status         sc.Status
		observationErr error
		want           []string
	}{
		{"native-healthy", sc.Status{Desired: "smart", Observed: "native_active", Health: "native_selected_https_recent", Selected: selected}, nil,
			[]string{"Requested: Smart Routing (TUN)", "native Core active", "Profile: " + selected}},
		{"native-degraded", sc.Status{Desired: "smart", Observed: "native_active", Health: "native_selected_path_degraded", Selected: selected}, nil,
			[]string{"Requested: Smart Routing (TUN)", "selected path degraded"}},
		{"native-synthetic", sc.Status{Desired: "smart", Observed: "native_active", Health: "native_selected_synthetic_qa_only", Selected: selected}, nil,
			[]string{"Requested: Smart Routing (TUN)", "synthetic QA health only"}},
		{"native-starting", sc.Status{Desired: "smart", Observed: "native_active", Health: "native_health_starting", Selected: selected}, nil,
			[]string{"Requested: Smart Routing (TUN)", "starting"}},
		{"native-failed-recovery", sc.Status{Desired: "smart", Observed: "native_failed", Health: "native_recovery_unverified", Selected: selected}, sc.Fault("guard_pending", "native resources may remain"),
			[]string{"Requested: Smart Routing (TUN)", "recovery unverified"}},
		{"direct-unverified", sc.Status{Desired: "direct", Observed: "inactive", Health: "not_tested"}, nil,
			[]string{"Requested: Direct", "host route unverified"}},
		{"proxy-active", sc.Status{Desired: "proxy", Observed: "active", Health: "not_tested"}, nil,
			[]string{"Requested: Proxy Only", "Proxy Only service active"}},
		{"malformed-private-profile", sc.Status{Desired: "smart", Observed: "native_active", Health: "native_selected_https_recent", Selected: "vless://secret-token"}, nil,
			[]string{"State: unverified"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := p.menuStateFromStatus(tc.status, tc.observationErr)
			for _, part := range tc.want {
				if !strings.Contains(got, part) {
					t.Fatalf("missing %q in %q", part, got)
				}
			}
			if tc.status.Desired == "smart" && strings.Contains(got, "Requested: Direct") {
				t.Fatalf("routed/recovering host was mislabeled Direct: %q", got)
			}
			if strings.Contains(got, "secret-token") || strings.Contains(got, "VPN path verified") {
				t.Fatalf("untrusted status or fabricated VPN path proof: %q", got)
			}
		})
	}
}

func TestOperatorMenuSafeDisconnectReusesCLIForEveryMode(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "no-state"), "", 0)
	in, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err = io.WriteString(writer, "7\n0\n"); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old }()
	var calls []string
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return menuWithRunner(m, func(_ *sc.Manager, args ...string) int {
			calls = append(calls, strings.Join(args, " "))
			return 0
		})
	})
	if code != 0 || stderr != "" || len(calls) != 1 || calls[0] != "disconnect" ||
		!strings.Contains(stdout, "7 Disconnect / Return to Direct") {
		t.Fatalf("menu and shared Disconnect drift: exit=%d calls=%q out=%q stderr=%q", code, calls, stdout, stderr)
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("display or stubbed Disconnect initialized manager state")
	}
}

// Real native Smart Routing must be reachable from the ordinary operator menu
// through exactly the same CLI command, while incomplete or canceled prompts
// never dispatch, initialize private state, or imply an already-safe host.
func TestOperatorMenuGuardedNativeConnectDispatchAndCancellation(t *testing.T) {
	cases := []struct {
		name, input, want, successText string
	}{
		{"underlay-eof", "21\n", "", ""},
		{"underlay-back", "21\nback\n0\n", "", ""},
		{"underlay-empty", "21\n\n0\n", "", ""},
		{"policy-eof", "21\neth0\n", "", ""},
		{"policy-cancel", "21\neth0\ncancel\n0\n", "", ""},
		{"policy-invalid", "21\neth0\n3\n0\n", "", ""},
		{"policy-empty", "21\neth0\n\n0\n", "", ""},
		{"confirmation-eof", "21\neth0\n1\nCONNECT-SMART", "", ""},
		{"confirmation-wrong", "21\neth0\n1\nYES\n0\n", "", ""},
		{"confirmation-back", "21\neth0\n1\nback\n0\n", "", ""},
		{"iran-direct", "21\neth0\n1\nCONNECT-SMART\n0\n", "connect-smart --underlay-if eth0 --mode bypass_iran", "Core started under native guards"},
		{"all-public-vpn", "21\nens3\n2\nCONNECT-SMART\n0\n", "connect-smart --underlay-if ens3 --mode default", "Core started under native guards"},
		{"read-native-health", "22\n0\n", "native-status", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := sc.New(filepath.Join(t.TempDir(), "uninitialized-state"), "", 0)
			in, wr, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(wr, tc.input); err != nil {
				t.Fatal(err)
			}
			wr.Close()
			old := os.Stdin
			os.Stdin = in
			defer func() { os.Stdin = old; in.Close() }()
			var calls []string
			code, out, stderr := hostDriftCapturedOutput(t, func() int {
				return menuWithRunner(m, func(_ *sc.Manager, args ...string) int {
					calls = append(calls, strings.Join(args, " "))
					return 0
				})
			})
			if code != 0 || stderr != "" {
				t.Fatalf("menu failed: code=%d stderr=%s stdout=%s", code, stderr, out)
			}
			if tc.want == "" {
				if len(calls) != 0 || strings.Contains(out, "Core started under native guards") {
					t.Fatalf("canceled/invalid menu action dispatched or claimed success: calls=%q out=%s", calls, out)
				}
			} else if len(calls) != 1 || calls[0] != tc.want {
				t.Fatalf("shared command mismatch: got %q, want %q; stdout=%s", calls, tc.want, out)
			}
			if tc.successText != "" && !strings.Contains(out, tc.successText) {
				t.Fatalf("successful command guidance missing: %s", out)
			}
			if tc.name == "all-public-vpn" &&
				(!strings.Contains(out, "including Iran, via VPN") ||
					!strings.Contains(out, "Protected/private and explicit Direct exceptions remain Direct")) {
				t.Fatalf("default-mode policy guidance incorrectly implies Iran bypass or ignores explicit exceptions: %s", out)
			}
			if !strings.Contains(out, "NOT RELEASE-READY") {
				t.Fatalf("menu falsely implies general-host readiness: %s", out)
			}
			if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
				t.Fatalf("menu initialized private state without real operation: %v", err)
			}
		})
	}
}

func TestOperatorMenuNativeConnectionFailureDoesNotClaimStarted(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "no-state"), "", 0)
	in, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(wr, "21\neth0\n1\nCONNECT-SMART\n0\n"); err != nil {
		t.Fatal(err)
	}
	wr.Close()
	old := os.Stdin
	os.Stdin = in
	defer func() { os.Stdin = old; in.Close() }()
	var called []string
	code, out, stderr := hostDriftCapturedOutput(t, func() int {
		return menuWithRunner(m, func(_ *sc.Manager, args ...string) int {
			called = append(called, strings.Join(args, " "))
			return 1 // CLI refusal, even though the operator supplied confirmation.
		})
	})
	if code != 0 || stderr != "" || len(called) != 1 ||
		called[0] != "connect-smart --underlay-if eth0 --mode bypass_iran" {
		t.Fatalf("failed command dispatch differed: %v %q %s", code, called, stderr)
	}
	if strings.Contains(out, "Core started under native guards") || strings.Contains(out, "Inspect option 22 (native-status)") {
		t.Fatalf("menu claimed native success after CLI refused: %s", out)
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("failed CLI dispatch in isolated runner created state")
	}
}

func TestOperatorMenuNativeOptionsVisibleAtWideAndNarrowWidths(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "uninitialized"), "", 0)
	for _, width := range []int{30, 42, 78} {
		var out bytes.Buffer
		p := operatorPresenter{out: &out, width: width}
		p.menu(m, false)
		for _, want := range []string{"21 Smart Routing (guarded QA)", "22 Native Guard / Recovery Status", "7 Disconnect / Return to Direct"} {
			if !strings.Contains(out.String(), want) {
				t.Fatalf("width %d missing %q: %s", width, want, out.String())
			}
		}
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("menu presentation changed private state")
	}
}
