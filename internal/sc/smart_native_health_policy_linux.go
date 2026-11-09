//go:build linux

package sc

// Active-policy observation complements the official Core's own routing.
// It does not install routes, adopt ownership or replace native recovery.
// Health traffic uses the selected mark 0x2023 (not SO_BINDTODEVICE): the
// official sing-box auto_redirect kernel rule sends that mark to its TUN
// table. Binding directly to a TUN interface fails ENETUNREACH on supported
// Debian 12/13 auto_redirect configurations and falsely reports VPN loss.

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const nativeSelectedMark = 0x2023

type nativeHealthKernelReader struct{}

func (nativeHealthKernelReader) output(ctx context.Context, binary string, args ...string) (string, error) {
	var path string
	switch binary {
	case "ip":
		path = nativeIPPath
	case "nft":
		path = nativeNFTPath
	default:
		return "", Fault("guard_unavailable", "unexpected native health inspector")
	}
	if e := verifyTrustedIPPath("/", path, 0); e != nil {
		return "", e
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "LANG=C"}
	cmd.Dir = "/"
	// Reuse the bounded native iproute2 output writer: a full nftables table
	// must not allocate an arbitrary amount of memory on a root-run guard.
	var out boundedIPOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 250 * time.Millisecond
	if e := cmd.Run(); e != nil || ctx.Err() != nil {
		return "", Fault("guard_unavailable", "selected routing kernel evidence unavailable")
	}
	return out.String(), nil
}

// Inspect no mutable routes or policy. Treat any missing/changed ownership
// boundary as loss of positive health proof. The post-probe read prevents
// reporting healthy after the native kernel capture has vanished.
func inspectNativeHealthPolicy(ctx context.Context, r interface {
	output(context.Context, string, ...string) (string, error)
}, p nativeRedirectRecovery, targets []nativeProbeTarget) error {
	if len(targets) == 0 || !smartTUNDeviceName.MatchString(p.TunnelIF) ||
		!smartTUNDeviceName.MatchString(p.UnderlayIF) || p.Table != NativePolicyTableIndex || p.Rule != NativePolicyRuleIndex {
		return Fault("guard_unavailable", "invalid native health policy identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, family := range []string{"-4", "-6"} {
		data, e := r.output(ctx, "ip", family, "rule", "show")
		if e != nil {
			return e
		}
		found := map[int]int{}
		for _, line := range strings.Split(data, "\n") {
			parts := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
			if parts == nil {
				continue
			}
			pref, parseErr := strconv.Atoi(parts[1])
			if parseErr != nil {
				return Fault("guard_unavailable", "invalid native policy RPDB record")
			}
			want := ""
			switch pref {
			case 1:
				if strings.HasPrefix(parts[2], "from all lookup ") && parts[2] != "from all lookup 254" {
					found[pref]++
				} else {
					return Fault("guard_unavailable", "native redirect identity conflict")
				}
				continue
			case p.Rule:
				want = fmt.Sprintf("from all fwmark 0x2024 goto %d", p.Rule+2)
			case p.Rule + 1:
				want = fmt.Sprintf("from all fwmark 0x2023 lookup %d", p.Table)
			case p.Rule + 2:
				want = "from all nop"
			default:
				if strings.Contains(parts[2], fmt.Sprintf("lookup %d", p.Table)) {
					want = fmt.Sprintf("not from all fwmark 0x2024 lookup %d", p.Table)
					if parts[2] != want {
						return Fault("guard_unavailable", "foreign native policy table reference")
					}
				}
			}
			if want != "" {
				if parts[2] != want {
					return Fault("guard_unavailable", "native policy RPDB identity changed")
				}
				found[pref]++
			}
		}
		for _, pref := range []int{1, p.Rule, p.Rule + 1, p.Rule + 2} {
			if found[pref] != 1 {
				return Fault("guard_unavailable", "native policy RPDB incomplete")
			}
		}
	}
	routes, e := r.output(ctx, "ip", "-4", "route", "show", "table", strconv.Itoa(p.Table))
	if e != nil {
		return e
	}
	if !strings.Contains(routes, "dev "+p.TunnelIF) || !strings.HasPrefix(strings.TrimSpace(routes), "default via ") {
		return Fault("guard_unavailable", "selected TUN policy table changed")
	}
	for _, t := range targets {
		route, e := r.output(ctx, "ip", "-4", "route", "get", t.IP, "mark", "0x2023")
		if e != nil {
			return e
		}
		// Route-get must independently prove this exact marked flow goes to the
		// selected native TUN table, not host main/Direct or a foreign interface.
		if !strings.Contains(route, " dev "+p.TunnelIF+" ") ||
			!strings.Contains(route, fmt.Sprintf(" table %d ", p.Table)) ||
			!strings.Contains(route, " mark 0x2023") {
			return Fault("guard_unavailable", "selected health mark could route Direct")
		}
	}
	nft, e := r.output(ctx, "nft", "list", "table", "inet", "sing-box")
	if e != nil {
		return e
	}
	required := []string{"chain prerouting_prematch {", "chain output_prematch {", "chain output {", "chain prerouting {",
		"type route hook output priority mangle + 1;", "type nat hook output priority mangle + 2;",
		"iifname \"" + p.TunnelIF + "\" return", "meta l4proto tcp counter", "redirect to :"}
	for _, item := range required {
		if !strings.Contains(nft, item) {
			return Fault("guard_unavailable", "native output redirect capture incomplete")
		}
	}
	known := map[string]bool{"prerouting_prematch": true, "output_prematch": true, "output": true, "output_udp_icmp": true, "input": true, "prerouting": true, "prerouting_udp_icmp": true}
	for _, match := range nativeChainLine.FindAllStringSubmatch(nft, -1) {
		if !known[match[1]] {
			return Fault("guard_unavailable", "native output redirect has foreign chain")
		}
	}
	return nil
}
