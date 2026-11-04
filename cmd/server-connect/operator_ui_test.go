package main

import (
	"bufio"
	"bytes"
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
	for _, want := range []string{"Advanced diagnostics", "11 Path Diagnostics", "12 Selective Plan", "20 Guarded Smart TUN"} {
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
	for _, code := range []string{"guard_pending", "unsupported_host", "service_conflict", "invalid_arguments", "routing_rules_conflict", "routing_rules_hash_mismatch", "routing_rules_missing", "operation_failed"} {
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
