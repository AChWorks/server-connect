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

// Callers request `ip -N` to force numeric table identities: a local
// rt_tables alias must not conceal foreign references to the reserved table.
// Parse the canonical iproute2 RPDB body as tokens so only a real lookup
// target (not a numeric prefix or an unrelated rule) is considered a
// reference. Both address families are inspected before any mutation.
func nativeRuleReferencesTable(body string, table int) bool {
	fields := strings.Fields(body)
	for i := 0; i+1 < len(fields); i++ {
		if (fields[i] == "lookup" || fields[i] == "table") && fields[i+1] == strconv.Itoa(table) {
			return true
		}
	}
	return false
}

func recoverNativeRedirect(parent context.Context, r nativeKernelRunner, p nativeRedirectRecovery) error {
	return recoverNativeRedirectWithVerifiedOrphan(parent, r, p, false)
}

// The official Core's abnormal SIGKILL teardown can remove its randomized
// redirect-table identity and nft table but leave exactly shaped 14200-series
// and 32768 RPDB rules. Without the identity the ordinary recovery must
// continue to refuse adoption. A caller that already verified this same
// current-boot, consumed Core-start claim and independently stopped Core may
// allow ONLY this orphan layout after separate absence/collision checks.
func recoverNativeRedirectWithVerifiedOrphan(parent context.Context, r nativeKernelRunner, p nativeRedirectRecovery, claimedCoreStart bool) error {
	if !smartTUNDeviceName.MatchString(p.TunnelIF) || !smartTUNDeviceName.MatchString(p.UnderlayIF) ||
		p.TunnelIF == p.UnderlayIF || p.TunnelIF == "lo" || p.UnderlayIF == "lo" ||
		p.Table != NativePolicyTableIndex || p.Rule != NativePolicyRuleIndex {
		return errors.New("invalid native recovery scope")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	rules := make([]nativeRule, 0, 16)
	for _, family := range []string{"-4", "-6"} {
		raw, e := r.output(ctx, "ip", "-N", family, "rule", "show")
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
	// The fixed 32768 fallback is a Core-owned identity only at that exact
	// priority. Preinspect every reference to the reserved policy table,
	// including those outside the 14200-series, before scheduling any delete.
	// A matching body at an arbitrary priority is never proof of ownership.
	fallbackBody := fmt.Sprintf("not from all fwmark 0x2024 lookup %d", p.Table)
	for _, rule := range rules {
		if rule.priority == 32768 && rule.body != fallbackBody {
			return errors.New("native recovery: foreign fixed fallback priority")
		}
		if nativeRuleReferencesTable(rule.body, p.Table) &&
			!(rule.priority == p.Rule+1 &&
				rule.body == fmt.Sprintf("from all fwmark 0x2023 lookup %d", p.Table)) &&
			!(rule.priority == 32768 && rule.body == fallbackBody) {
			return errors.New("native recovery: foreign reserved-table reference")
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
		if pref == 32768 {
			fallbackRules = append(fallbackRules, nativeAction{"ip", []string{rule.family, "rule", "del", "pref", "32768"}})
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
	seenRoutes := make(map[string]bool)
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
				dev := p.UnderlayIF
				if line != want {
					// sing-box 1.14.3 also creates this exact loopback
					// redirect for Docker's standard bridge when it exists.
					// Do not accept arbitrary extra interfaces or routes.
					if family != "-4" || line != "local 127.0.0.1 dev docker0 scope host" {
						return errors.New("native recovery: unexpected redirect-table route")
					}
					dev = "docker0"
				}
				identity := family + ":" + dev
				if seenRoutes[identity] {
					return errors.New("native recovery: duplicate redirect-table route")
				}
				seenRoutes[identity] = true
				routes = append(routes, nativeAction{"ip", []string{family, "route", "del", "table", strconv.Itoa(redirectTable), "local", host, "dev", dev}})
			}
		}
	}
	tables, e := r.output(ctx, "nft", "list", "tables")
	if e != nil {
		return e
	}
	countTable := 0
	countDockerTable := 0
	for _, line := range strings.Split(tables, "\n") {
		switch strings.TrimSpace(line) {
		case "table inet sing-box":
			countTable++
		case "table ip filter":
			countDockerTable++
		}
	}
	if countDockerTable > 1 {
		return errors.New("native recovery: ambiguous Docker filter table")
	}
	var dockerActions []nativeAction
	if countDockerTable == 1 {
		dockerActions, e = inspectNativeDockerRecovery(ctx, r, p.TunnelIF)
		if e != nil {
			return e
		}
		if len(dockerActions) > 0 && redirectTable == 0 {
			return errors.New("native recovery: Docker rules lack redirect identity")
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
	// A killed Core may have released its nft table, random-table rule
	// and TUN interface while its exact fixed-slot RPDB rules remain.
	// This is not a general orphan cleanup: the caller must have already
	// verified the one-use Core-start receipt under the native Manager lock.
	// Refuse even exact RPDB patterns if the Core's nft identity, Docker
	// compatibility rules, any TUN, or unattributed redirect routes survive.
	// The previously checked fixed table must be empty; priorities and
	// complete rule bodies were checked and de-duplicated above.
	if redirectTable == 0 && (len(coreRules) != 0 || len(fallbackRules) != 0) {
		if !claimedCoreStart || countTable != 0 || len(dockerActions) != 0 {
			return errors.New("native recovery: policy orphan without verified Core-start ownership")
		}
		links, linkErr := r.output(ctx, "ip", "-o", "link", "show")
		if linkErr != nil {
			return linkErr
		}
		for _, line := range strings.Split(links, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.SplitN(strings.TrimSpace(line), ": ", 3)
			if len(fields) < 2 {
				return errors.New("native recovery: unparseable orphan interface inventory")
			}
			if strings.SplitN(fields[1], "@", 2)[0] == p.TunnelIF {
				return errors.New("native recovery: orphan TUN still exists")
			}
		}
		for _, item := range []struct {
			family, address string
		}{{"-4", "127.0.0.1"}, {"-6", "::1"}} {
			allRoutes, routeErr := r.output(ctx, "ip", item.family, "route", "show", "table", "all")
			if routeErr != nil {
				return routeErr
			}
			for _, line := range strings.Split(allRoutes, "\n") {
				parts := strings.Fields(line)
				if len(parts) >= 4 && parts[0] == "local" &&
					parts[1] == item.address && parts[2] == "dev" &&
					parts[3] == p.UnderlayIF {
					return errors.New("native recovery: orphan redirect route still exists without table identity")
				}
			}
		}
	}
	// Preinspect all objects before changing any. Keep priority-1 redirect
	// identity until AFTER the nft table is deleted: an interrupted nft delete
	// must leave the randomized table discoverable for the next exact retry.
	// A partial priority-1 deletion still leaves the other family's same table.
	all := append(append(append([]nativeAction{}, routes...), coreRules...), fallbackRules...)
	if countTable == 1 {
		all = append(all, nativeAction{"nft", []string{"delete", "table", "inet", "sing-box"}})
	}
	// Docker compatibility rules belong to a foreign-owned chain. Remove
	// only the two exact Core-created TUN rules, before retiring the
	// randomized-table identity. Failure leaves the identity for retry.
	all = append(all, dockerActions...)
	for _, a := range all {
		if e := r.run(ctx, a.binary, a.args...); e != nil {
			return e
		}
	}
	if countDockerTable == 1 {
		remaining, err := inspectNativeDockerRecovery(ctx, r, p.TunnelIF)
		if err != nil || len(remaining) != 0 {
			return errors.New("native recovery: Docker compatibility cleanup unverified")
		}
	}
	for _, a := range priorityOne {
		if e := r.run(ctx, a.binary, a.args...); e != nil {
			return e
		}
	}
	// Proof of Direct/off means managed RPDB and nft surface is actually gone.
	for _, family := range []string{"-4", "-6"} {
		raw, e := r.output(ctx, "ip", "-N", family, "rule", "show")
		if e != nil {
			return e
		}
		for _, line := range strings.Split(raw, "\n") {
			match := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
			if match == nil {
				continue
			}
			n, _ := strconv.Atoi(match[1])
			if n == 1 || n == 32768 || (n >= p.Rule && n <= p.Rule+10) ||
				nativeRuleReferencesTable(match[2], p.Table) {
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
