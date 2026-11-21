//go:build linux

package sc

// A short-lived, operation-bound OUTPUT admission barrier closes the gap
// between systemd Type=exec reporting success and sing-box installing its TUN
// and auto_redirect policy. It is NOT a second router or a Direct/off kill switch.
// The barrier never authorizes routing: it temporarily rejects new unmarked
// public underlay egress while preserving reply, local/on-link and selected
// Core bootstrap traffic. Only exact, receipt-bound nft objects are removed.
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const nativeStartupFile = "native-startup.json"
const nativeStartupChain = "output"
const nativeStartupPriority = -100

var nativeStartupTablePattern = regexp.MustCompile("^sc_pre_[0-9a-f]{32}$")

type nativeStartupPlan struct {
	Version        int      `json:"version"`
	Name           string   `json:"name"`
	UnderlayIF     string   `json:"underlay_if"`
	PeerIPs        []string `json:"peer_ips"`
	PeerPort       uint16   `json:"peer_port"`
	DirectPrefixes []string `json:"direct_prefixes"`
	Resolvers      []string `json:"resolvers"`
}

type nativeStartupRule struct {
	Text string
	Expr []any
}

func nativeStartupMatch(left map[string]any, right any) any {
	return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
}
func nativeStartupMeta(key string, right any) any {
	return nativeStartupMatch(map[string]any{"meta": map[string]any{"key": key}}, right)
}
func nativeStartupPayload(family string, value string) any {
	address, err := netip.ParsePrefix(value)
	if err == nil {
		// nft canonicalizes an exact /32 or /128 prefix to a literal address.
		// Strict ownership receipts must match actual kernel normalization.
		if address.Bits() == address.Addr().BitLen() {
			return nativeStartupMatch(map[string]any{"payload": map[string]any{"protocol": family, "field": "daddr"}}, address.Addr().String())
		}
		return nativeStartupMatch(map[string]any{"payload": map[string]any{"protocol": family, "field": "daddr"}},
			map[string]any{"prefix": map[string]any{"addr": address.Masked().Addr().String(), "len": address.Bits()}})
	}
	return nativeStartupMatch(map[string]any{"payload": map[string]any{"protocol": family, "field": "daddr"}}, value)
}
func nativeStartupPort(proto string, port uint16) any {
	return nativeStartupMatch(map[string]any{"payload": map[string]any{"protocol": proto, "field": "dport"}}, int(port))
}
func nativeStartupAccept() any { return map[string]any{"accept": nil} }
func nativeStartupReject(family string) any {
	t := "icmp"
	if family == "ip6" {
		t = "icmpv6"
	}
	return map[string]any{"reject": map[string]any{"type": t, "expr": "port-unreachable"}}
}
func nativeStartupRules(p nativeStartupPlan) ([]nativeStartupRule, error) {
	if p.Version != 1 || !nativeStartupTablePattern.MatchString(p.Name) ||
		!nativeInterfaceName.MatchString(p.UnderlayIF) || p.UnderlayIF == "lo" ||
		p.PeerPort == 0 || len(p.PeerIPs) == 0 || len(p.PeerIPs) > 64 ||
		len(p.DirectPrefixes) > 64 || len(p.Resolvers) > 64 {
		return nil, Fault("invalid_state", "native startup guard plan invalid")
	}
	r := []nativeStartupRule{
		{"ct direction reply accept", []any{nativeStartupMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, "reply"), nativeStartupAccept()}},
		{"meta mark 0x2024 accept", []any{nativeStartupMeta("mark", NativePolicyOutputMark), nativeStartupAccept()}},
		{"oifname \"lo\" accept", []any{nativeStartupMeta("oifname", "lo"), nativeStartupAccept()}},
	}
	// Independent local/private traffic remains reachable during activation.
	for _, item := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
		"::1/128", "fc00::/7", "fe80::/10"} {
		pfx, _ := netip.ParsePrefix(item)
		family := "ip"
		if pfx.Addr().Is6() {
			family = "ip6"
		}
		r = append(r, nativeStartupRule{family + " daddr " + item + " accept",
			[]any{nativeStartupPayload(family, item), nativeStartupAccept()}})
	}
	appendIPs := func(items []string, purpose string) error {
		old := ""
		for _, address := range items {
			a, e := netip.ParseAddr(address)
			if e != nil || !a.IsValid() || a.IsUnspecified() || a.IsMulticast() ||
				a.Is4In6() || (old != "" && address <= old) || a.String() != address {
				return Fault("invalid_state", "native startup guard addresses invalid")
			}
			old = address
			family := "ip"
			if a.Is6() {
				family = "ip6"
			}
			port := p.PeerPort
			if purpose == "resolver" {
				port = 53
			}
			for _, proto := range []string{"tcp", "udp"} {
				r = append(r, nativeStartupRule{fmt.Sprintf("%s daddr %s %s dport %d accept", family, address, proto, port),
					[]any{nativeStartupPayload(family, address), nativeStartupPort(proto, port), nativeStartupAccept()}})
			}
		}
		return nil
	}
	if err := appendIPs(p.PeerIPs, "peer"); err != nil {
		return nil, err
	}
	if err := appendIPs(p.Resolvers, "resolver"); err != nil {
		return nil, err
	}
	old := ""
	for _, cidr := range p.DirectPrefixes {
		prefix, e := netip.ParsePrefix(cidr)
		if e != nil || !prefix.IsValid() || prefix.Masked() != prefix ||
			prefix.Bits() == 0 || prefix.String() != cidr || (old != "" && cidr <= old) {
			return nil, Fault("invalid_state", "native startup guard connected prefixes invalid")
		}
		old = cidr
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		r = append(r, nativeStartupRule{family + " daddr " + cidr + " accept",
			[]any{nativeStartupPayload(family, cidr), nativeStartupAccept()}})
	}
	for _, family := range []string{"ip", "ip6"} {
		cidr := "0.0.0.0/0"
		if family == "ip6" {
			cidr = "::/0"
		}
		r = append(r, nativeStartupRule{fmt.Sprintf("oifname \"%s\" %s daddr %s reject", p.UnderlayIF, family, cidr),
			[]any{nativeStartupMeta("oifname", p.UnderlayIF), nativeStartupPayload(family, cidr), nativeStartupReject(family)}})
	}
	return r, nil
}
func nativeStartupScript(plan nativeStartupPlan) (string, error) {
	rules, err := nativeStartupRules(plan)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n chain %s {\n  type filter hook output priority %d; policy accept;\n",
		plan.Name, nativeStartupChain, nativeStartupPriority)
	for _, r := range rules {
		fmt.Fprintf(&b, "  %s\n", r.Text)
	}
	b.WriteString(" }\n}\n")
	return b.String(), nil
}
func nativeStartupPlanFor(session NativeSession, profile Profile) (nativeStartupPlan, error) {
	if len(session.HealthOperationID) != 32 || !journalHex64.MatchString(session.ConfigSHA256) {
		return nativeStartupPlan{}, Fault("invalid_state", "native startup operation identity unavailable")
	}
	var remote struct {
		Server string `json:"server"`
		Port   uint16 `json:"server_port"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &fields) != nil ||
		json.Unmarshal(fields["server"], &remote.Server) != nil ||
		json.Unmarshal(fields["server_port"], &remote.Port) != nil ||
		remote.Server == "" || remote.Port == 0 {
		return nativeStartupPlan{}, Fault("invalid_state", "selected Core bootstrap endpoint unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var ips []netip.Addr
	if a, e := netip.ParseAddr(remote.Server); e == nil {
		ips = []netip.Addr{a.Unmap()}
	} else {
		lookup, e := net.DefaultResolver.LookupIPAddr(ctx, remote.Server)
		if e != nil {
			return nativeStartupPlan{}, Fault("guard_unavailable", "selected bootstrap name resolution unavailable")
		}
		for _, item := range lookup {
			if a, ok := netip.AddrFromSlice(item.IP); ok {
				ips = append(ips, a.Unmap())
			}
		}
	}
	names := map[string]bool{}
	for _, a := range ips {
		if a.IsValid() && !a.IsUnspecified() && !a.IsMulticast() {
			names[a.String()] = true
		}
	}
	if len(names) == 0 {
		return nativeStartupPlan{}, Fault("guard_unavailable", "no usable selected upstream endpoint")
	}
	p := nativeStartupPlan{Version: 1, Name: "sc_pre_" + session.HealthOperationID,
		UnderlayIF: session.UnderlayIF, PeerPort: remote.Port}
	for addr := range names {
		p.PeerIPs = append(p.PeerIPs, addr)
	}
	sort.Strings(p.PeerIPs)
	iface, e := net.InterfaceByName(session.UnderlayIF)
	if e != nil {
		return nativeStartupPlan{}, Fault("guard_unavailable", "native underlay interface missing")
	}
	addrs, e := iface.Addrs()
	if e != nil {
		return nativeStartupPlan{}, Fault("guard_unavailable", "native underlay address inventory unavailable")
	}
	prefixes := map[string]bool{}
	for _, addr := range addrs {
		prefix, e := netip.ParsePrefix(addr.String())
		if e == nil && prefix.IsValid() && prefix.Bits() > 0 {
			prefixes[prefix.Masked().String()] = true
		}
	}
	for value := range prefixes {
		p.DirectPrefixes = append(p.DirectPrefixes, value)
	}
	sort.Strings(p.DirectPrefixes)
	// Only pinned OS bootstrap resolvers, not arbitrary public UDP/53, may
	// traverse the temporary guard. Localhost resolvers are already permitted.
	raw, e := os.ReadFile("/etc/resolv.conf")
	if e != nil {
		return nativeStartupPlan{}, Fault("guard_unavailable", "host resolver inventory unavailable")
	}
	resolvers := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		if len(f) >= 2 && f[0] == "nameserver" {
			if addr, e := netip.ParseAddr(f[1]); e == nil && addr.IsValid() && !addr.IsUnspecified() {
				resolvers[addr.Unmap().String()] = true
			}
		}
	}
	for value := range resolvers {
		p.Resolvers = append(p.Resolvers, value)
	}
	sort.Strings(p.Resolvers)
	if _, e := nativeStartupRules(p); e != nil {
		return nativeStartupPlan{}, e
	}
	return p, nil
}
func (m *Manager) readNativeStartupPlan(session NativeSession) (nativeStartupPlan, error) {
	raw, e := readRegular(filepath.Join(m.Dir, nativeStartupFile))
	if e != nil {
		return nativeStartupPlan{}, e
	}
	sum := sha256.Sum256(raw)
	if len(raw) > 8192 || hex.EncodeToString(sum[:]) != session.StartupGuardSHA256 ||
		rejectAmbiguousJournalJSON(raw) != nil {
		return nativeStartupPlan{}, Fault("invalid_state", "native startup guard private plan changed")
	}
	var p nativeStartupPlan
	if strictReplyGuardJSON(raw, &p) != nil || p.Name != session.StartupGuardName || p.UnderlayIF != session.UnderlayIF {
		return nativeStartupPlan{}, Fault("invalid_state", "native startup guard plan differs from operation")
	}
	if _, e := nativeStartupRules(p); e != nil {
		return nativeStartupPlan{}, e
	}
	return p, nil
}
func nativeStartupPresent(ctx context.Context, r nativeReplyGuardReader, name string) (bool, error) {
	if !nativeStartupTablePattern.MatchString(name) {
		return false, Fault("invalid_state", "invalid native startup table name")
	}
	text, e := r.output(ctx, "nft", "list", "tables")
	if e != nil {
		return false, e
	}
	count := 0
	for _, line := range strings.Split(text, "\n") {
		if line == "table inet "+name {
			count++
		} else if strings.HasSuffix(line, " "+name) {
			return false, Fault("service_conflict", "foreign native startup nft family")
		}
	}
	if count > 1 {
		return false, Fault("service_conflict", "duplicate native startup table")
	}
	return count == 1, nil
}
func nativeStartupReceipt(ctx context.Context, r nativeReplyGuardReader, p nativeStartupPlan) (uint64, error) {
	raw, e := r.output(ctx, "nft", "-j", "-a", "list", "table", "inet", p.Name)
	if e != nil {
		return 0, e
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if len(raw) > 65536 || strictReplyGuardJSON([]byte(raw), &doc) != nil {
		return 0, Fault("guard_unavailable", "native startup nft state invalid")
	}
	rows := doc.Nftables
	if len(rows) > 0 && len(rows[0]) == 1 && rows[0]["metainfo"] != nil {
		rows = rows[1:]
	}
	rules, e := nativeStartupRules(p)
	if e != nil {
		return 0, e
	}
	if len(rows) != len(rules)+2 {
		return 0, Fault("service_conflict", "native startup nft object count differs")
	}
	var table struct {
		Family, Name string
		Handle       uint64
	}
	var chain struct {
		Family, Table, Name, Type, Hook, Policy string
		Handle                                  uint64
		Prio                                    int
	}
	if len(rows[0]) != 1 || len(rows[1]) != 1 || rows[0]["table"] == nil || rows[1]["chain"] == nil ||
		strictReplyGuardJSON(rows[0]["table"], &table) != nil || strictReplyGuardJSON(rows[1]["chain"], &chain) != nil ||
		table.Family != "inet" || table.Name != p.Name || table.Handle == 0 ||
		chain.Family != "inet" || chain.Table != p.Name || chain.Name != nativeStartupChain || chain.Handle == 0 ||
		chain.Type != "filter" || chain.Hook != "output" || chain.Prio != nativeStartupPriority || chain.Policy != "accept" {
		return 0, Fault("service_conflict", "native startup nft hook altered")
	}
	for i, expected := range rules {
		row := rows[i+2]
		if len(row) != 1 || row["rule"] == nil {
			return 0, Fault("service_conflict", "native startup nft rule missing")
		}
		var actual struct {
			Family, Table, Chain string
			Handle               uint64
			Expr                 []json.RawMessage
		}
		if strictReplyGuardJSON(row["rule"], &actual) != nil ||
			actual.Family != "inet" || actual.Table != p.Name || actual.Chain != nativeStartupChain || actual.Handle == 0 ||
			len(actual.Expr) != len(expected.Expr) {
			return 0, Fault("service_conflict", "native startup nft rule changed")
		}
		for j, want := range expected.Expr {
			var got any
			if strictReplyGuardJSON(actual.Expr[j], &got) != nil || !reflect.DeepEqual(got, want) {
				// JSON numbers decode as float64; canonicalize the generated expected
				// expression through the same decoder before comparing.
				b, _ := json.Marshal(want)
				var canonical any
				_ = json.Unmarshal(b, &canonical)
				if !reflect.DeepEqual(got, canonical) {
					return 0, Fault("service_conflict", fmt.Sprintf("native startup nft policy expression differs at rule %d expression %d actual=%v expected=%v", i, j, got, canonical))
				}
			}
		}
	}
	return table.Handle, nil
}
func requireNativeStartupGuardClaim(ctx context.Context, r nativeReplyGuardReader,
	p nativeStartupPlan, expectedHandle uint64) error {
	if expectedHandle == 0 {
		return Fault("guard_pending", "native startup guard has no committed handle")
	}
	tables, err := r.output(ctx, "nft", "list", "tables")
	if err != nil {
		return err
	}
	count := 0
	for _, line := range strings.Split(tables, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 3 && parts[0] == "table" && strings.HasPrefix(parts[2], "sc_pre_") {
			if parts[2] != p.Name || parts[1] != "inet" {
				return Fault("service_conflict", "foreign native startup containment owner")
			}
			count++
		}
	}
	if count != 1 {
		return Fault("guard_unavailable", "native startup containment missing or ambiguous")
	}
	handle, err := nativeStartupReceipt(ctx, r, p)
	if err != nil {
		return err
	}
	if handle != expectedHandle {
		return Fault("service_conflict", "native startup containment handle was replaced")
	}
	return nil
}
func nativeStartupInstall(ctx context.Context, r nativeReplyGuardWriter, p nativeStartupPlan) (uint64, error) {
	exists, e := nativeStartupPresent(ctx, r, p.Name)
	if e != nil || exists {
		return 0, Fault("service_conflict", "native startup table is already occupied")
	}
	script, e := nativeStartupScript(p)
	if e != nil {
		return 0, e
	}
	if e = r.applyReplyGuardScript(ctx, script); e != nil {
		return 0, e
	}
	return nativeStartupReceipt(ctx, r, p)
}
func nativeStartupRecover(ctx context.Context, r nativeReplyGuardCASRunner,
	p nativeStartupPlan, expectedHandle uint64, phase string) error {
	if phase != "preparing" && phase != "armed" && phase != "releasing" && phase != "released" {
		return Fault("invalid_state", "native startup guard phase invalid")
	}
	before, e := r.replyGuardGeneration()
	if e != nil {
		return e
	}
	present, e := nativeStartupPresent(ctx, r, p.Name)
	if e != nil {
		return e
	}
	if !present {
		if phase == "armed" {
			return Fault("guard_pending", "armed native startup containment disappeared")
		}
		return nil
	}
	handle, e := nativeStartupReceipt(ctx, r, p)
	if e != nil {
		return e
	}
	if expectedHandle != 0 && expectedHandle != handle {
		return Fault("service_conflict", "native startup containment handle changed")
	}
	after, e := r.replyGuardGeneration()
	if e != nil || before == 0 || before != after {
		return Fault("guard_pending", "native startup nft generation changed")
	}
	if e = r.deleteReplyGuardCAS(handle, after); e != nil {
		return e
	}
	present, e = nativeStartupPresent(ctx, r, p.Name)
	if e != nil || present {
		return Fault("guard_pending", "native startup containment removal unverified")
	}
	return nil
}

// A manager may only release containment after the exact independent Core
// interception witness is present. A first selected HTTPS check can follow;
// application traffic must never race ahead of effective kernel routing.
func (m *Manager) releaseNativeStartupAfterReady(session NativeSession) error {
	return m.withLock(func() error {
		current, e := m.readNativeSession()
		if e != nil {
			return e
		}
		if current != session || current.StartupGuardPhase != "armed" || current.StartupGuardHandle == 0 {
			return Fault("guard_pending", "native startup session changed during readiness")
		}
		current.StartupGuardPhase = "releasing"
		raw, e := json.Marshal(current)
		if e != nil {
			return e
		}
		return put(filepath.Join(m.Dir, nativeSessionFile), raw)
	})
}
func (m *Manager) finishNativeStartupRelease(session NativeSession) error {
	plan, e := m.readNativeStartupPlan(session)
	if e != nil {
		return e
	}
	if e = nativeStartupRecover(context.Background(), nativeSystemRunner{}, plan, session.StartupGuardHandle, "releasing"); e != nil {
		return e
	}
	return m.withLock(func() error {
		current, e := m.readNativeSession()
		if e != nil {
			return e
		}
		if current.StartupGuardName != session.StartupGuardName || current.StartupGuardPhase != "releasing" ||
			current.HealthOperationID != session.HealthOperationID {
			return Fault("guard_pending", "native startup operation changed while releasing")
		}
		current.StartupGuardPhase = "released"
		raw, e := json.Marshal(current)
		if e != nil {
			return e
		}
		return put(filepath.Join(m.Dir, nativeSessionFile), raw)
	})
}

// Used by recovery after exact Core-owned routing teardown. No generic
// firewall flush, no deletion by table name alone and no foreign adoption.
func (m *Manager) recoverNativeStartupWithSession(ctx context.Context, r nativeReplyGuardCASRunner, session NativeSession) error {
	if session.StartupGuardName == "" {
		return nil
	} // independently verified historical claims
	p, e := m.readNativeStartupPlan(session)
	if e != nil {
		return e
	}
	return nativeStartupRecover(ctx, r, p, session.StartupGuardHandle, session.StartupGuardPhase)
}

// Bounded helper for writing a fresh private, one-use startup plan before
// installing the nft table. A preexisting unrelated system nft table is never
// accepted by this staging operation.
func (m *Manager) stageNativeStartupUnderLock(session *NativeSession, profile Profile) error {
	p, e := nativeStartupPlanFor(*session, profile)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	sum := sha256.Sum256(raw)
	session.StartupGuardName = p.Name
	session.StartupGuardSHA256 = hex.EncodeToString(sum[:])
	session.StartupGuardPhase = "preparing"
	if e = put(filepath.Join(m.Dir, nativeStartupFile), raw); e != nil {
		return e
	}
	claim, e := json.Marshal(session)
	if e != nil {
		return e
	}
	if e = put(filepath.Join(m.Dir, nativeSessionFile), claim); e != nil {
		return e
	}
	handle, e := nativeStartupInstall(context.Background(), nativeSystemRunner{}, p)
	if e != nil {
		return e
	}
	session.StartupGuardHandle = handle
	session.StartupGuardPhase = "armed"
	committed, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return put(filepath.Join(m.Dir, nativeSessionFile), committed)
}

// The independent guard may tick while the Core is still constructing its
// kernel policy. A bounded startup grace is safe ONLY if the exact nft packet
// barrier is already effective; a missing/replaced table is a fatal fault.
func (m *Manager) nativeGuardedStartupGrace(claim NativeSession, health NativeHealthState, now int64) (bool, error) {
	if health.Phase != "starting" || claim.StartupGuardPhase != "armed" ||
		now < health.StartedMS || now-health.StartedMS >= nativeHealthGraceMS {
		return false, nil
	}
	p, e := m.readNativeStartupPlan(claim)
	if e != nil {
		return false, e
	}
	if e = requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, p, claim.StartupGuardHandle); e != nil {
		return false, e
	}
	return true, nil
}

// Positive readiness: Core service active AND exact TUN/redirect kernel
// interception, not merely a process PID or interface that appeared early.
func (m *Manager) nativeReadyKernelPolicy(session NativeSession, scope string) error {
	raw, e := readRegular(filepath.Join(m.Dir, nativeConfigFile))
	if e != nil {
		return e
	}
	targets, e := nativeHealthTargets(raw, scope)
	if e != nil {
		return e
	}
	if e = inspectNativeHealthPolicy(context.Background(), nativeHealthKernelReader{}, session.recoveryScope(), targets); e != nil {
		return e
	}
	plan, e := m.readNativeStartupPlan(session)
	if e != nil {
		return e
	}
	handle, e := nativeStartupReceipt(context.Background(), nativeSystemRunner{}, plan)
	if e != nil || handle != session.StartupGuardHandle {
		return Fault("guard_unavailable", "native startup containment not verified during readiness")
	}
	return nil
}
