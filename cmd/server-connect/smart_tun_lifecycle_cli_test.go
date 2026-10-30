package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// A saved policy must be one immutable input to fresh admission. Even an
// explicitly empty routing flag is a conflicting source of operator intent;
// rejecting it before opening the store prevents partial/mixed Apply.
func TestSmartTUNSavedApplyRejectsMixedInputsBeforeStateAccess(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unopened-state")
	m := sc.New(dir, filepath.Join(dir, "missing-core"), 0)
	for _, flagName := range []string{
		"tunnel-if", "underlay-if", "tunnel-ipv4", "tunnel-ipv6",
		"management-peer", "domestic-cidr", "protected-cidr",
		"domestic-ipv6-cidr", "ipv6-vpn-cidr", "ipv6-direct-cidr",
	} {
		for _, value := range []string{"", "private-input-must-not-be-printed"} {
			t.Run(flagName+"/"+value, func(t *testing.T) {
				code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
					return run(true, m, []string{
						"smart-tun-trial-apply", "--saved",
						"--" + flagName + "=" + value,
					})
				})
				if code == 0 || stderr != "" ||
					!strings.Contains(stdout, `"code":"invalid_arguments"`) ||
					strings.Contains(stdout, "private-input-must-not-be-printed") {
					t.Fatalf("mixed saved policy input accepted/leaked: exit=%d out=%s err=%s", code, stdout, stderr)
				}
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Fatalf("rejected mixed input touched private state: %v", err)
				}
			})
		}
	}
}

func TestSmartTUNLifecycleCLIRejectsInvalidSyntaxWithoutMutation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "unopened-state")
	m := sc.New(dir, filepath.Join(dir, "missing-core"), 0)
	for _, args := range [][]string{
		{"smart-tun-trial-apply", "--saved", "extra"},
		{"smart-tun-trial-apply", "--saved", "--deadline-seconds", "invalid"},
		{"smart-tun-trial-policy", "--file", "untrusted"},
		{"smart-tun-trial-disconnect", "--unexpected"},
		{"smart-tun-trial-disconnect", "--revision", "-1"},
		{"smart-tun-trial-disconnect", "--operation-id", strings.Repeat("a", 32), "extra"},
		{"smart-tun-trial-clear", "--revision", "invalid"},
		{"smart-tun-trial-clear", "--qa-kill-at", "after-cleanup-intent", "extra"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
				return run(true, m, args)
			})
			if code == 0 || stderr != "" || !strings.Contains(stdout, `"code":"invalid_arguments"`) {
				t.Fatalf("invalid lifecycle syntax accepted: exit=%d out=%s err=%s", code, stdout, stderr)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("invalid lifecycle syntax touched private state: %v", err)
			}
		})
	}
}
