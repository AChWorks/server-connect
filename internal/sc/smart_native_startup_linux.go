//go:build linux

package sc

// One operation-bound OUTPUT containment is installed before publishing Smart
// and remains effective until exact Core/kernel recovery commits Direct.
// It is not a router and never persists after verified Off: the filter runs
// after Core's own auto_redirect hooks to allow authenticated selected TUN
// traffic (0x2023), Core-marked Direct/underlay (0x2024), replies and protected
// destinations, while rejecting new unmarked public fallback even if Core dies
// and the TUN disappears before ExecStopPost can run.
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
)

const nativeStartupFile = "native-startup.json"
const nativeStartupChain = "output"
const nativeStartupPriority = 200

var nativeStartupTablePattern = regexp.MustCompile("^sc_pre_[0-9a-f]{32}$")

type nativeStartupPlan struct {
	Version        int      `json:"version"`
	Name           string   `json:"name"`
	UnderlayIF     string   `json:"underlay_if"`
	DirectPrefixes []string `json:"direct_prefixes"`
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
		len(p.DirectPrefixes) > 64 {
		return nil, Fault("invalid_state", "native startup guard plan invalid")
	}
	r := []nativeStartupRule{
		{"ct direction reply accept", []any{nativeStartupMatch(map[string]any{"ct": map[string]any{"key": "direction"}}, "reply"), nativeStartupAccept()}},
		// Core's route/redirect hooks run before this later OUTPUT admission.
		// Ordinary application packets can therefore reach the selected TUN,
		// while Core-originated public Direct/underlay still uses mark 0x2024.
		{"meta mark 0x2023 accept", []any{nativeStartupMeta("mark", nativeSelectedMark), nativeStartupAccept()}},
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
		// Smart is host-wide, not confined to the chosen physical NIC.
		// Any unmarked non-protected public egress must remain blocked
		// even if a second/default WAN path appears during activation.
		r = append(r, nativeStartupRule{fmt.Sprintf("%s daddr %s reject", family, cidr),
			[]any{nativeStartupPayload(family, cidr), nativeStartupReject(family)}})
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
func nativeStartupPlanFor(session NativeSession) (nativeStartupPlan, error) {
	if len(session.HealthOperationID) != 32 || !journalHex64.MatchString(session.ConfigSHA256) {
		return nativeStartupPlan{}, Fault("invalid_state", "native startup operation identity unavailable")
	}
	// Only exact already-connected prefixes may bypass the temporary
	// filter. The official Core's marked sockets (0x2024) are the sole
	// permitted public bootstrap path; a peer IP/port or OS resolver
	// exception could let unrelated applications leak direct traffic.
	p := nativeStartupPlan{Version: 1, Name: "sc_pre_" + session.HealthOperationID,
		UnderlayIF: session.UnderlayIF}
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
	// Public OS resolver addresses are NOT blanket exemptions. The
	// Core's marked bootstrap sockets are already allowed above; otherwise
	// any unrelated host app could leak raw DNS while desired=smart.
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
	// A committed handle must be checked against the complete original
	// policy and against parallel sc_pre owners before the generation-CAS
	// delete. A preparing receipt has no handle yet; it may only remove an
	// independently verified exact instance of its staged plan.
	handle := expectedHandle
	if handle != 0 {
		if e := requireNativeStartupGuardClaim(ctx, r, p, handle); e != nil {
			return e
		}
	} else {
		handle, e = nativeStartupReceipt(ctx, r, p)
		if e != nil {
			return e
		}
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

// A healthy or degraded Native session must retain its operation-bound
// public egress containment until the same session commits Direct/off.
// A table name alone cannot satisfy this check: verify every rule and its
// original handle before publishing any further selected-path health proof.
func (m *Manager) verifyNativeLiveOutputGuard(session NativeSession) error {
	if session.StartupGuardPhase != "armed" || session.StartupGuardHandle == 0 {
		return Fault("guard_pending", "native lifetime OUTPUT guard is not armed")
	}
	plan, err := m.readNativeStartupPlan(session)
	if err != nil {
		return err
	}
	return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, session.StartupGuardHandle)
}

// Every deliberate terminal stop must restore the *existing* operation-bound
// packet barrier before Core or its TUN can disappear. The same guard is used
// for supervised child replacement. During a partial startup/rearm, a
// preparing receipt can be recovered only against its exact precommitted plan;
// an unknown or replaced nft object is never adopted or deleted here.
// Caller holds Manager .lock and the outer native transition, or is the
// quiescent ExecStopPost owner.
func (m *Manager) ensureNativeStopBarrierLocked() error {
	state, err := m.load()
	if err != nil {
		return err
	}
	session, err := m.readNativeSession()
	if os.IsNotExist(err) {
		if state.Desired == "smart" {
			return Fault("guard_pending", "Smart shutdown has no native containment receipt")
		}
		return nil
	}
	if err != nil {
		return err
	}
	// Pre-commit rollback already has Direct desired, and must not install
	// a new filter merely to retire a never-activated startup receipt.
	if state.Desired != "smart" {
		return nil
	}
	if err := m.validateNativeSessionConfig(session); err != nil {
		return err
	}
	if session.StartupGuardName == "" {
		return Fault("guard_pending", "Smart shutdown has no operation-bound output barrier")
	}
	plan, err := m.readNativeStartupPlan(session)
	if err != nil {
		return err
	}
	switch session.StartupGuardPhase {
	case "armed":
		return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, session.StartupGuardHandle)
	case "released":
		return m.rearmNativeOperationBarrierLocked(session)
	case "releasing":
		present, err := nativeStartupPresent(context.Background(), nativeSystemRunner{}, plan.Name)
		if err != nil {
			return err
		}
		if present {
			return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, session.StartupGuardHandle)
		}
		// Interrupted release: the old table has independently disappeared.
		// Retire its stale handle before preparing the new guard.
		session.StartupGuardPhase = "released"
		raw, err := json.Marshal(session)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
			return err
		}
		return m.rearmNativeOperationBarrierLocked(session)
	case "preparing":
		present, err := nativeStartupPresent(context.Background(), nativeSystemRunner{}, plan.Name)
		if err != nil {
			return err
		}
		handle := uint64(0)
		if present {
			handle, err = nativeStartupReceipt(context.Background(), nativeSystemRunner{}, plan)
		} else {
			handle, err = nativeStartupInstall(context.Background(), nativeSystemRunner{}, plan)
		}
		if err != nil {
			return err
		}
		session.StartupGuardPhase, session.StartupGuardHandle = "armed", handle
		raw, err := json.Marshal(session)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
			return err
		}
		return requireNativeStartupGuardClaim(context.Background(), nativeSystemRunner{}, plan, handle)
	default:
		return Fault("guard_pending", "native shutdown containment phase invalid")
	}
}

// Called with the Manager lock only after exact Core-owned networking has
// been independently restored and desired=direct has been saved. A lifetime
// guard's final removal must have durable intent BEFORE the nft CAS: if the
// process dies after deletion, retry may accept an absent table only under
// this same operation's releasing receipt (never under an armed claim).
func (m *Manager) recoverNativeStartupWithSession(ctx context.Context, r nativeReplyGuardCASRunner, session NativeSession) error {
	if session.StartupGuardName == "" {
		return nil
	} // independently verified historical claims
	state, err := m.load()
	if err != nil {
		return err
	}
	if state.Desired != "direct" {
		return Fault("guard_pending", "native lifetime guard release requires durable Direct")
	}
	current, err := m.readNativeSession()
	if err != nil {
		return err
	}
	if current != session {
		return Fault("guard_pending", "native lifetime guard release belongs to another operation")
	}
	p, err := m.readNativeStartupPlan(session)
	if err != nil {
		return err
	}
	if session.StartupGuardPhase == "armed" {
		// Never authorize an already-absent or altered guard with a newly
		// written release intent. Validate the original plan and table handle
		// before the fsynced operation receipt is changed to releasing.
		if err := requireNativeStartupGuardClaim(ctx, r, p, session.StartupGuardHandle); err != nil {
			return err
		}
		session.StartupGuardPhase = "releasing"
		raw, err := json.Marshal(session)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeSessionFile), raw); err != nil {
			return err
		}
	}
	return nativeStartupRecover(ctx, r, p, session.StartupGuardHandle, session.StartupGuardPhase)
}

// Bounded helper for writing a fresh private, one-use startup plan before
// installing the nft table. A preexisting unrelated system nft table is never
// accepted by this staging operation.
func (m *Manager) stageNativeStartupUnderLock(session *NativeSession) error {
	p, e := nativeStartupPlanFor(*session)
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
	// A guard which remains armed for the entire Smart lifetime must not
	// keep a genuinely READY child in startup grace forever. Once the
	// distinct sing-box child and actual native TUN/RPDB/redirect are
	// independently proved, let Health run its normal HTTPS probe while
	// retaining the *same* effective guard against unexpected Core death.
	if _, _, e := m.nativeCoreChildIdentity(); e == nil {
		if e := m.nativeReadyKernelPolicy(claim, health.ProbeScope); e == nil {
			return false, nil
		}
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
