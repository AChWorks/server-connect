//go:build linux

package sc

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This narrowly restores the known official sing-tun auto_redirect layout.
// A caller must first stop the owned Core and hold a durable pre-activation
// claim proving the reserved slots/table were free. It must not run as a
// generic "clean networking" command or be used to adopt foreign resources.
type nativeRedirectRecovery struct {
	TunnelIF   string
	UnderlayIF string
	Table      int
	Rule       int
}
type nativeKernelRunner interface {
	output(context.Context, string, ...string) (string, error)
	run(context.Context, string, ...string) error
}
type nativeSystemRunner struct{}

func (nativeSystemRunner) output(ctx context.Context, binary string, args ...string) (string, error) {
	b, e := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	if e != nil {
		// iproute2 exits 2 for an absent routing table (IPv4 and IPv6).
		// Treat only this exact kernel observation as an empty table.
		if binary == "ip" && len(args) == 5 && args[1] == "route" &&
			args[2] == "show" && args[3] == "table" &&
			strings.HasPrefix(string(b), "Error: ipv") &&
			strings.Contains(string(b), "FIB table does not exist.") {
			return "", nil
		}
		return "", fmt.Errorf("native %s inspection failed: %w", binary, e)
	}
	return string(b), nil
}
func (nativeSystemRunner) run(ctx context.Context, binary string, args ...string) error {
	if _, e := exec.CommandContext(ctx, binary, args...).CombinedOutput(); e != nil {
		return fmt.Errorf("native %s recovery action failed: %w", binary, e)
	}
	return nil
}

type nativeRule struct {
	family   string
	priority int
	body     string
}
type nativeAction struct {
	binary string
	args   []string
}

var nativeRuleLine = regexp.MustCompile("^([0-9]+):\\s+(.+)$")
var nativeChainLine = regexp.MustCompile("(?m)^\\s*chain ([a-zA-Z0-9_]+) \\{")

func recoverNativeRedirect(parent context.Context, r nativeKernelRunner, p nativeRedirectRecovery) error {
	if !smartTUNDeviceName.MatchString(p.TunnelIF) || !smartTUNDeviceName.MatchString(p.UnderlayIF) ||
		p.TunnelIF == p.UnderlayIF || p.TunnelIF == "lo" || p.UnderlayIF == "lo" ||
		p.Table != NativePolicyTableIndex || p.Rule != NativePolicyRuleIndex {
		return errors.New("invalid native recovery scope")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	rules := make([]nativeRule, 0, 16)
	for _, family := range []string{"-4", "-6"} {
		raw, e := r.output(ctx, "ip", family, "rule", "show")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			parts := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
			if parts == nil {
				return errors.New("native recovery: malformed RPDB rule")
			}
			priority, e := strconv.Atoi(parts[1])
			if e != nil {
				return errors.New("native recovery: invalid priority")
			}
			rules = append(rules, nativeRule{family, priority, parts[2]})
		}
	}
	// Resolve the Core's *second*, randomized auto_redirect table, whose
	// priority-1 RPDB rule ignores iproute2_table_index.
	redirectTable := 0
	var coreRules, fallbackRules, priorityOne []nativeAction
	for _, rule := range rules {
		pref := rule.priority
		if pref == 1 {
			prefix := "from all lookup "
			if !strings.HasPrefix(rule.body, prefix) {
				return errors.New("native recovery: foreign priority-1 rule")
			}
			v, e := strconv.Atoi(strings.TrimPrefix(rule.body, prefix))
			if e != nil || v <= 255 || v == p.Table || (redirectTable != 0 && redirectTable != v) {
				return errors.New("native recovery: invalid redirect table identity")
			}
			redirectTable = v
			priorityOne = append(priorityOne, nativeAction{"ip", []string{rule.family, "rule", "del", "pref", "1", "table", strconv.Itoa(v)}})
		}
		if pref >= p.Rule && pref <= p.Rule+10 {
			want := ""
			switch pref {
			case p.Rule:
				want = fmt.Sprintf("from all fwmark 0x2024 goto %d", p.Rule+2)
			case p.Rule + 1:
				want = fmt.Sprintf("from all fwmark 0x2023 lookup %d", p.Table)
			case p.Rule + 2:
				want = "from all nop"
			}
			if want == "" || rule.body != want {
				return errors.New("native recovery: foreign managed RPDB rule")
			}
			coreRules = append(coreRules, nativeAction{"ip", []string{rule.family, "rule", "del", "pref", strconv.Itoa(pref)}})
		}
		if strings.Contains(rule.body, fmt.Sprintf("lookup %d", p.Table)) && pref > p.Rule+10 {
			if rule.body != fmt.Sprintf("not from all fwmark 0x2024 lookup %d", p.Table) {
				return errors.New("native recovery: foreign table reference")
			}
			fallbackRules = append(fallbackRules, nativeAction{"ip", []string{rule.family, "rule", "del", "pref", strconv.Itoa(pref)}})
		}
	}
	if len(fallbackRules) > 2 {
		return errors.New("native recovery: duplicate fallback rules")
	}
	// Never delete a priority without a unique identity, even if the first
	// matching line has the expected shape.
	for _, a := range append(append([]nativeAction{}, coreRules...), append(fallbackRules, priorityOne...)...) {
		family, index := a.args[0], a.args[4]
		count := 0
		for _, rule := range rules {
			if rule.family == family && strconv.Itoa(rule.priority) == index {
				count++
			}
		}
		if count != 1 {
			return errors.New("native recovery: conflicting RPDB priority")
		}
	}
	for _, family := range []string{"-4", "-6"} {
		raw, e := r.output(ctx, "ip", family, "route", "show", "table", strconv.Itoa(p.Table))
		if e != nil {
			return e
		}
		if strings.TrimSpace(raw) != "" {
			return errors.New("native recovery: TUN policy table not empty")
		}
	}
	var routes []nativeAction
	if redirectTable != 0 {
		for _, family := range []string{"-4", "-6"} {
			raw, e := r.output(ctx, "ip", family, "route", "show", "table", strconv.Itoa(redirectTable))
			if e != nil {
				return e
			}
			host := "127.0.0.1"
			if family == "-6" {
				host = "::1"
			}
			for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Linux reports IPv4 local routes with "scope host"; IPv6
				// reports its native metric and preference. Match both
				// exactly, never a foreign additional route in this table.
				want := fmt.Sprintf("local %s dev %s scope host", host, p.UnderlayIF)
				if family == "-6" {
					want = fmt.Sprintf("local %s dev %s metric 1024 pref medium", host, p.UnderlayIF)
				}
				if line != want {
					return errors.New("native recovery: unexpected redirect-table route")
				}
				routes = append(routes, nativeAction{"ip", []string{family, "route", "del", "table", strconv.Itoa(redirectTable), "local", host, "dev", p.UnderlayIF}})
			}
		}
	} else if len(coreRules) > 0 || len(fallbackRules) > 0 {
		return errors.New("native recovery: policy orphan without redirect identity")
	}
	tables, e := r.output(ctx, "nft", "list", "tables")
	if e != nil {
		return e
	}
	countTable := 0
	for _, line := range strings.Split(tables, "\n") {
		if strings.TrimSpace(line) == "table inet sing-box" {
			countTable++
		}
	}
	if countTable > 1 {
		return errors.New("native recovery: ambiguous nft table identity")
	}
	if countTable == 1 {
		if redirectTable == 0 {
			return errors.New("native recovery: nft table lacks redirect identity")
		}
		body, e := r.output(ctx, "nft", "list", "table", "inet", "sing-box")
		if e != nil {
			return e
		}
		if !strings.Contains(body, "chain prerouting_prematch {") ||
			!strings.Contains(body, "chain output_prematch {") ||
			!strings.Contains(body, fmt.Sprintf("iifname %q", p.TunnelIF)) {
			return errors.New("native recovery: nft table not owned Core shape")
		}
		known := map[string]bool{"prerouting_prematch": true, "output_prematch": true, "output": true,
			"output_udp_icmp": true, "input": true, "prerouting": true, "prerouting_udp_icmp": true}
		for _, match := range nativeChainLine.FindAllStringSubmatch(body, -1) {
			if !known[match[1]] {
				return errors.New("native recovery: foreign nft chain")
			}
		}
	}
	// Preinspect all objects before changing any. The route-first order keeps
	// the randomized table discoverable via priority 1 if cleanup is interrupted.
	all := append(append(append([]nativeAction{}, routes...), coreRules...), fallbackRules...)
	all = append(all, priorityOne...)
	if countTable == 1 {
		all = append(all, nativeAction{"nft", []string{"delete", "table", "inet", "sing-box"}})
	}
	for _, a := range all {
		if e := r.run(ctx, a.binary, a.args...); e != nil {
			return e
		}
	}
	// Proof of Direct/off means managed RPDB and nft surface is actually gone.
	for _, family := range []string{"-4", "-6"} {
		raw, e := r.output(ctx, "ip", family, "rule", "show")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(raw, "\n") {
			match := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
			if match == nil {
				continue
			}
			n, _ := strconv.Atoi(match[1])
			if n == 1 || (n >= p.Rule && n <= p.Rule+10) ||
				strings.Contains(match[2], fmt.Sprintf("lookup %d", p.Table)) {
				return errors.New("native recovery: managed RPDB policy remains")
			}
		}
		if redirectTable != 0 {
			raw, e = r.output(ctx, "ip", family, "route", "show", "table", strconv.Itoa(redirectTable))
			if e != nil || strings.TrimSpace(raw) != "" {
				return errors.New("native recovery: redirect table remains")
			}
		}
	}
	after, e := r.output(ctx, "nft", "list", "tables")
	if e != nil || strings.Contains(after, "table inet sing-box") {
		return errors.New("native recovery: nft table remains")
	}
	return nil
}
