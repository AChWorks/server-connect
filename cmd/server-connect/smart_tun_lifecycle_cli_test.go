package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// Retired v4 experiment commands must not appear in help or initialize state.
func TestRetiredV4CommandsAreInert(t *testing.T) {
	for _, name := range []string{
		"smart-tun-trial-apply", "smart-tun-trial-confirm", "smart-tun-trial-policy",
		"smart-tun-trial-disconnect", "smart-tun-trial-reconcile-idle-guard",
		"smart-tun-trial-status", "smart-tun-trial-clear", "smart-tun-trial-health",
	} {
		t.Run(name, func(t *testing.T) {
			if strings.Contains(helpText, name) {
				t.Fatalf("retired v4 operator command still advertised: %s", name)
			}
			dir := filepath.Join(t.TempDir(), "unopened-state")
			m := sc.New(dir, filepath.Join(dir, "missing-core"), 0)
			code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
				return run(true, m, []string{name, "--operation-id", strings.Repeat("a", 32)})
			})
			if code != 1 || stderr != "" || !strings.Contains(stdout, `"code":"unknown_command"`) ||
				strings.Contains(stdout, `"data"`) {
				t.Fatalf("retired v4 command dispatched: %s (%d, %q, %q)", name, code, stdout, stderr)
			}
			if _, err := os.Lstat(dir); !os.IsNotExist(err) {
				t.Fatalf("retired command touched state: %s, %v", name, err)
			}
		})
	}
}

func TestNativeHealthExecutorStillRefusesUnexpectedArguments(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unopened-state")
	m := sc.New(dir, filepath.Join(dir, "missing-core"), 0)
	for _, args := range [][]string{
		{"native-health-executor", "--unexpected"},
		{"native-health-executor", "extra"},
	} {
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
		if code != 1 || stderr != "" || !strings.Contains(stdout, `"code":"invalid_arguments"`) {
			t.Fatalf("invalid native health syntax was not refused: %v (%d %s %s)", args, code, stdout, stderr)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("invalid command touched state: %v", err)
		}
	}
}
