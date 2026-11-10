package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestOperatorMenuIsReadOnlyOnFirstUseAndHidesLegacyUntilAdvanced(t *testing.T) {
	m := sc.New(filepath.Join(t.TempDir(), "not-installed"), "", 0)
	var out bytes.Buffer
	p := operatorPresenter{out: &out, width: 42}
	p.menu(m, false)
	basic := out.String()
	for _, want := range []string{"Server Connect", "0.1.0-dev", "State: not inspected", "NOT AVAILABLE", "18 Mode Overview", "19 Routing Rules", "a Toggle advanced", "0 Exit", "Choice:"} {
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
	for _, want := range []string{"Advanced diagnostics", "11 Path Diagnostics", "20 Guarded Smart TUN"} {
		if !strings.Contains(advanced, want) {
			t.Fatalf("advanced tool unavailable: %q", want)
		}
	}
	if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
		t.Fatal("opening advanced menu created manager state")
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

// A refused VM-only Apply must not direct the operator to confirm an operation
// that never started. This is an unprivileged, state-less refusal test; it
// never exercises a real host TUN, systemd unit or network route.
func TestOperatorMenuFailedVMApplyNeverOffersConfirmation(t *testing.T) {
	for _, tc := range []struct{ name, input, successAdvice string }{
		{"first-apply", "20\n2\nVM-CONNECT\n0\n", "For confirmation open a completely NEW SSH connection"},
		{"saved-reapply", "20\n3\nVM-RECONNECT\n0\n", "Open a NEW SSH connection to confirm the one-time challenge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := sc.New(filepath.Join(t.TempDir(), "uninstalled-state"), "", 0)
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
			code, out, stderr := hostDriftCapturedOutput(t, func() int { return menu(m) })
			if code != 0 || !strings.Contains(out, "Not completed:") || !strings.Contains(stderr, "Error [") || strings.Contains(out, tc.successAdvice) {
				t.Fatalf("refused trial implied successful Apply: code=%d out=%s err=%s", code, out, stderr)
			}
			if _, err := os.Lstat(m.Dir); !os.IsNotExist(err) {
				t.Fatal("refused VM trial created uninstalled product state")
			}
		})
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
	const base = "11\n" + one + "\n" + two + "\n"
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
		{"diagnose-first-cancel", "11\ncancel\n0\n", ""},
		{"diagnose-second-back", "11\n" + one + "\nback\n0\n", ""},
		{"diagnose-first-incomplete-eof", "11\n" + one, ""},
		{"diagnose-valid-proxy", base + "1\n0\n", "diagnose-path --via proxy --url " + one + " --url " + two},
		{"diagnose-valid-direct", base + "2\n0\n", "diagnose-path --via direct --url " + one + " --url " + two},
		{"retired-selective-menu", "12\n0\n", ""},
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
		{"vm-confirm-cancel-challenge", "20\n5\n0123456789abcdef\n3\ncancel\n0\n", ""},
		{"vm-confirm-valid", "20\n5\n0123456789abcdef\n3\nchallenge-token\n0\n", "smart-tun-trial-confirm --operation-id 0123456789abcdef --revision 3 --challenge challenge-token"},
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
