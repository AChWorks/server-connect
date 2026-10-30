package sc

// The native subtype shares the v4 guard/Off lifecycle, but never gives the
// core authority to create or remove host routing policy. Its deliberately
// fixed resource layout is only for the existing disconnected QA fixtures.
import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
)

const (
	smartTUNNativeIntent           = "smart_tun_native_pending_trial_v1"
	nativeTUNMarkMask       uint32 = 0x00ff0000
	nativeTUNCaptureMark    uint32 = 0x00530000
	nativeTUNBypassMark     uint32 = 0x00540000
	nativeTUNTable4                = 42424
	nativeTUNTable6                = 42426
	nativeTUNPriority              = 10400
	nativeTUNMetric                = 100
	nativeTUNFallbackMetric        = 42760
)

// An intent precedes the kernel call. Only an acknowledged, independently
// observed result may acquire a receipt. An exact-looking object without that
// receipt remains ambiguous; a protocol/tag/priority is not ownership proof.
type smartTUNNativeObject struct {
	Stage  string `json:"stage"`
	SHA256 string `json:"sha256"`
}

type smartTUNNativeFamily struct {
	Address         string               `json:"address"`
	Table           int                  `json:"table"`
	Rule            smartTUNNativeObject `json:"rule"`
	Route           smartTUNNativeObject `json:"route"`
	Fallback        smartTUNNativeObject `json:"fallback"`
	DependentSHA256 string               `json:"dependent_sha256"`
}

type smartTUNNativeNFTIdentity struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle"`
	SHA256 string `json:"sha256"`
}

// Every field is comparable, including the fixed family slots. Do not add a
// map/slice or compare Native pointers when refreshing an atomic journal inode.
type smartTUNNativeLedger struct {
	Version         int                           `json:"version"`
	NamespaceDev    uint64                        `json:"namespace_dev"`
	NamespaceIno    uint64                        `json:"namespace_ino"`
	UnderlayIndex   int                           `json:"underlay_index"`
	LinkIndex       int                           `json:"link_index"`
	LinkStage       string                        `json:"link_stage"`
	LinkSHA256      string                        `json:"link_sha256"`
	AddressSHA256   string                        `json:"address_sha256"`
	IPv4            smartTUNNativeFamily          `json:"ipv4"`
	IPv6            smartTUNNativeFamily          `json:"ipv6"`
	NFTName         string                        `json:"nft_name"`
	NFTHandle       uint64                        `json:"nft_handle"`
	NFT             smartTUNNativeObject          `json:"nft"`
	NFTCount        int                           `json:"nft_count"`
	NFTObjects      [24]smartTUNNativeNFTIdentity `json:"nft_objects"`
	StopReason      string                        `json:"stop_reason"`
	StartupVerified bool                          `json:"startup_verified"`
}

func sameSmartTUNTrial(a, b smartTUNTrialJournal) bool {
	an, bn := a.Native, b.Native
	as, bs := a.Supervised, b.Supervised
	a.Native, b.Native = nil, nil
	a.Supervised, b.Supervised = nil, nil
	return a == b && ((an == nil && bn == nil) || (an != nil && bn != nil && *an == *bn)) &&
		((as == nil && bs == nil) || (as != nil && bs != nil && *as == *bs))
}

func cloneSmartTUNTrial(record smartTUNTrialJournal) smartTUNTrialJournal {
	if record.Native != nil {
		native := *record.Native
		record.Native = &native
	}
	if record.Supervised != nil {
		supervised := *record.Supervised
		record.Supervised = &supervised
	}
	return record
}

func nativeObjectValid(object smartTUNNativeObject) bool {
	switch object.Stage {
	case "planned", "effect_possible":
		return object.SHA256 == ""
	case "observed", "remove_requested":
		return journalHex64.MatchString(object.SHA256)
	case "removed":
		return object.SHA256 == "" || journalHex64.MatchString(object.SHA256)
	}
	return false
}

func validateSmartTUNNative(record smartTUNTrialJournal) error {
	n := record.Native
	bad := func() error { return activationJournalError("native TUN identity or resource ledger is invalid") }
	if n == nil || n.Version != 1 || n.NamespaceDev == 0 || n.NamespaceIno == 0 || n.UnderlayIndex <= 1 ||
		record.EndpointIP != "10.254.72.2" || record.ManagementPeerIP != "10.254.72.2" ||
		record.TunnelInterface != "sctunqa0" || record.UnderlayInterface != "scqaedge0" ||
		n.NFTName != "scnt_"+record.OperationID || n.IPv4.Address != "172.31.99.1/30" || n.IPv4.Table != nativeTUNTable4 ||
		(n.IPv6.Address != "" && n.IPv6.Address != "fd73:99::1/64") || n.IPv6.Table != nativeTUNTable6 || !nativeObjectValid(n.NFT) {
		return bad()
	}
	if n.LinkIndex < 0 || n.LinkIndex == n.UnderlayIndex || n.LinkIndex == 1 {
		return bad()
	}
	switch n.LinkStage {
	case "planned", "create_possible":
		if n.LinkIndex != 0 || n.LinkSHA256 != "" || n.AddressSHA256 != "" {
			return bad()
		}
	case "bound", "persist_possible", "observed", "remove_requested":
		if n.LinkIndex < 2 || !journalHex64.MatchString(n.LinkSHA256) || !journalHex64.MatchString(n.AddressSHA256) {
			return bad()
		}
	case "removed":
		if n.LinkIndex != 0 && (!journalHex64.MatchString(n.LinkSHA256) || !journalHex64.MatchString(n.AddressSHA256)) {
			return bad()
		}
	default:
		return bad()
	}
	for _, family := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
		if !nativeObjectValid(family.Rule) || !nativeObjectValid(family.Route) || !nativeObjectValid(family.Fallback) {
			return bad()
		}
		if family.DependentSHA256 != "" && !journalHex64.MatchString(family.DependentSHA256) {
			return bad()
		}
		if family.Address == "" && (family.Rule.Stage != "planned" || family.Route.Stage != "planned" || family.Fallback.Stage != "planned") {
			return bad()
		}
		if n.LinkIndex > 0 && !journalHex64.MatchString(family.DependentSHA256) {
			return bad()
		}
	}
	if (n.NFT.Stage == "planned" || n.NFT.Stage == "effect_possible") && n.NFTHandle != 0 {
		return bad()
	}
	if (n.NFT.Stage == "observed" || n.NFT.Stage == "remove_requested") && n.NFTHandle == 0 {
		return bad()
	}
	if n.NFTCount < 0 || n.NFTCount > len(n.NFTObjects) || (n.StopReason != "" && n.StopReason != "off" && n.StopReason != "guard") {
		return bad()
	}
	for i, object := range n.NFTObjects {
		if i >= n.NFTCount {
			if object != (smartTUNNativeNFTIdentity{}) {
				return bad()
			}
			continue
		}
		if (object.Kind != "table" && object.Kind != "chain" && object.Kind != "rule") || object.Name == "" || object.Handle == 0 || !journalHex64.MatchString(object.SHA256) {
			return bad()
		}
	}
	if n.NFTCount != 0 {
		wanted := nativeNFTObjects(record)
		if n.NFTCount != len(wanted) || n.NFTObjects[0].Handle != n.NFTHandle {
			return bad()
		}
		for i, object := range wanted {
			for kind, value := range object {
				fields := value.(map[string]any)
				name, _ := fields["name"].(string)
				if kind == "rule" {
					name, _ = fields["chain"].(string)
				}
				hash, err := nativeNFTObjectHash([]map[string]any{object}, true)
				if err != nil || n.NFTObjects[i].Kind != kind || n.NFTObjects[i].Name != name || n.NFTObjects[i].SHA256 != hash {
					return bad()
				}
			}
		}
	}
	if (n.NFT.Stage == "observed" || n.NFT.Stage == "remove_requested") && n.NFTCount != len(nativeNFTObjects(record)) {
		return bad()
	}
	if (n.NFT.Stage == "planned" || n.NFT.Stage == "effect_possible") && n.NFTCount != 0 {
		return bad()
	}
	if record.CoreStartAttempted && n.LinkIndex == 0 {
		return bad()
	}
	if n.StartupVerified && !record.CoreStartAttempted {
		return bad()
	}
	if record.Phase == "trial_pending" {
		if n.StopReason != "" || n.LinkStage == "removed" || n.NFT.Stage == "remove_requested" || n.NFT.Stage == "removed" {
			return bad()
		}
		for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
			for _, object := range []smartTUNNativeObject{f.Rule, f.Route, f.Fallback} {
				if object.Stage == "remove_requested" || object.Stage == "removed" {
					return bad()
				}
			}
		}
		if n.NFT.Stage == "observed" && (!n.StartupVerified || n.LinkStage != "observed") {
			return bad()
		}
	}
	if record.Phase == "trial_stop_requested" && n.StopReason != "off" && n.StopReason != "guard" {
		return bad()
	}
	if record.Phase == "trial_recovered" && ((record.Revision == 2 && n.StopReason != "guard") || (record.Revision == 3 && n.StopReason != "off")) {
		return bad()
	}
	if (record.Phase == "trial_recovered" || record.Phase == "trial_cleanup_pending") && (record.CoreStartAttempted && !n.StartupVerified) {
		return bad()
	}
	if record.Phase == "trial_cleanup_pending" && n.StopReason != "off" && n.StopReason != "guard" {
		return bad()
	}
	if record.Phase == "trial_recovered" || record.Phase == "trial_cleanup_pending" {
		if n.LinkStage != "removed" || n.NFT.Stage != "removed" {
			return bad()
		}
		for _, f := range []smartTUNNativeFamily{n.IPv4, n.IPv6} {
			if f.Address != "" && (f.Rule.Stage != "removed" || f.Route.Stage != "removed" || f.Fallback.Stage != "removed") {
				return bad()
			}
		}
	}
	return nil
}

// Exact key sets at every level prevent null, case aliases or unknown native
// fields from becoming privileged deletion authority after decoding.
func strictSmartTUNNativeJSON(raw json.RawMessage) error {
	keys := map[string]bool{"version": true, "namespace_dev": true, "namespace_ino": true, "underlay_index": true, "link_index": true, "link_stage": true, "link_sha256": true, "address_sha256": true, "ipv4": true, "ipv6": true, "nft_name": true, "nft_handle": true, "nft": true, "nft_count": true, "nft_objects": true, "stop_reason": true, "startup_verified": true}
	if err := requireExactJournalKeys(raw, keys); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return activationJournalError("null native TUN member")
		}
	}
	objectKeys := map[string]bool{"stage": true, "sha256": true}
	checkObject := func(raw json.RawMessage) error {
		if err := requireExactJournalKeys(raw, objectKeys); err != nil {
			return err
		}
		var f map[string]json.RawMessage
		_ = json.Unmarshal(raw, &f)
		for _, v := range f {
			if len(v) < 2 || v[0] != '"' {
				return activationJournalError("native progress field must be a string")
			}
		}
		return nil
	}
	if err := checkObject(fields["nft"]); err != nil {
		return err
	}
	var objects []json.RawMessage
	if json.Unmarshal(fields["nft_objects"], &objects) != nil || len(objects) != 24 {
		return activationJournalError("native nft receipts must have the fixed bounded layout")
	}
	for _, object := range objects {
		if err := requireExactJournalKeys(object, map[string]bool{"kind": true, "name": true, "handle": true, "sha256": true}); err != nil {
			return err
		}
		var values map[string]json.RawMessage
		_ = json.Unmarshal(object, &values)
		for _, value := range values {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return activationJournalError("null native nft receipt")
			}
		}
	}
	for _, name := range []string{"ipv4", "ipv6"} {
		if err := requireExactJournalKeys(fields[name], map[string]bool{"address": true, "table": true, "rule": true, "route": true, "fallback": true, "dependent_sha256": true}); err != nil {
			return err
		}
		var f map[string]json.RawMessage
		_ = json.Unmarshal(fields[name], &f)
		for _, value := range f {
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return activationJournalError("null native family member")
			}
		}
		for _, slot := range []string{"rule", "route", "fallback"} {
			if err := checkObject(f[slot]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Keep Proxy Only's supported import dialect unchanged. This native path
// currently admits only the tested VLESS dialect and owns all path controls.
func smartTUNNativeConfig(profile Profile, options SmartTUNCandidateOptions) ([]byte, error) {
	if err := rejectAmbiguousJournalJSON(profile.Outbound); err != nil {
		return nil, Fault("trial_unsupported", "native profile JSON is ambiguous")
	}
	var outbound map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &outbound) != nil {
		return nil, Fault("trial_unsupported", "native profile is invalid")
	}
	allowed := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "uuid": true, "flow": true, "tls": true, "transport": true, "packet_encoding": true}
	for key := range outbound {
		if !allowed[key] {
			return nil, Fault("trial_unsupported", "native profile contains an unsupported egress control")
		}
	}
	var typ string
	_ = json.Unmarshal(outbound["type"], &typ)
	if typ != "vless" {
		return nil, Fault("trial_unsupported", "native fixture requires the tested VLESS outbound")
	}
	base, err := SmartTUNCandidateConfig(profile, options)
	if err != nil {
		return nil, err
	}
	var config map[string]any
	decoder := json.NewDecoder(bytes.NewReader(base))
	decoder.UseNumber()
	if decoder.Decode(&config) != nil {
		return nil, Fault("trial_unsupported", "cannot construct native core policy")
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	inbound["address"] = []any{}
	inbound["stack"] = "gvisor"
	inbound["auto_route"], inbound["auto_redirect"] = false, false
	delete(inbound, "route_exclude_address")
	delete(inbound, "strict_route")
	for _, value := range config["outbounds"].([]any) {
		value.(map[string]any)["routing_mark"] = nativeTUNBypassMark
	}
	config["route"].(map[string]any)["default_mark"] = nativeTUNBypassMark
	return json.MarshalIndent(config, "", "  ")
}

func nativeTUNPlannedFamily(address string, table int) smartTUNNativeFamily {
	p := smartTUNNativeObject{Stage: "planned"}
	return smartTUNNativeFamily{Address: address, Table: table, Rule: p, Route: p, Fallback: p}
}

func nativeFamilyFlag(family int) string {
	if family == 6 {
		return "-6"
	}
	return "-4"
}
func nativeFamily(n *smartTUNNativeLedger, family int) *smartTUNNativeFamily {
	if family == 6 {
		return &n.IPv6
	}
	return &n.IPv4
}

func nativeRouteArgs(record smartTUNTrialJournal, family int, kind, verb string) []string {
	f := nativeFamily(record.Native, family)
	if kind == "rule" {
		return []string{nativeFamilyFlag(family), "rule", verb, "priority", strconv.Itoa(nativeTUNPriority), "fwmark", fmt.Sprintf("0x%x/0x%x", nativeTUNCaptureMark, nativeTUNMarkMask), "table", strconv.Itoa(f.Table), "protocol", trialProtocol}
	}
	args := []string{nativeFamilyFlag(family), "route", verb}
	if kind == "fallback" {
		return append(args, "unreachable", "default", "table", strconv.Itoa(f.Table), "metric", strconv.Itoa(nativeTUNFallbackMetric), "protocol", trialProtocol)
	}
	prefix := netip.MustParsePrefix(f.Address)
	return append(args, "default", "dev", record.TunnelInterface, "table", strconv.Itoa(f.Table), "metric", strconv.Itoa(nativeTUNMetric), "protocol", trialProtocol, "scope", "link", "src", prefix.Addr().String())
}

// Both chains receive the SAME mandatory exception expressions. The filter
// independently classifies eligible traffic: loss of capture cannot turn an
// unmarked VPN-required packet into an allowed Direct packet.
func nativeNFTObjects(record smartTUNTrialJournal) []map[string]any {
	n := record.Native
	objects := []map[string]any{{"table": map[string]any{"family": "inet", "name": n.NFTName, "comment": "server-connect:" + record.OperationID}}}
	meta := func(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	ret := map[string]any{"return": nil}
	protected := func(family int) any {
		// Emit the pinned nft JSON representation directly: anonymous
		// prefixes are address-sorted and full-length prefixes are literals.
		prefixes := []string{"10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"}
		if family == 6 {
			prefixes = []string{"::1/128", "fc00::/7", "fe80::/10"}
		}
		items := []any{}
		for _, raw := range prefixes {
			p := netip.MustParsePrefix(raw)
			if p.Bits() == p.Addr().BitLen() {
				items = append(items, p.Addr().String())
			} else {
				items = append(items, map[string]any{"prefix": map[string]any{"addr": p.Addr().String(), "len": p.Bits()}})
			}
		}
		protocol := "ip"
		if family == 6 {
			protocol = "ip6"
		}
		return match(map[string]any{"payload": map[string]any{"protocol": protocol, "field": "daddr"}}, map[string]any{"set": items})
	}
	// nft lists all chain headers before each chain's ordered rules. Keep
	// creation and expected receipt in that shape without sorting observations.
	for _, chain := range []string{"capture", "guard"} {
		kind, hook, priority := "route", "output", -150
		// OUTPUT route rerouting changes skb_dst, not that hook's original
		// state.out. POSTROUTING exposes the actual selected egress device.
		if chain == "guard" {
			kind, hook, priority = "filter", "postrouting", 0
		}
		objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": n.NFTName, "name": chain, "type": kind, "hook": hook, "prio": priority, "policy": "accept"}})
	}
	for _, chain := range []string{"capture", "guard"} {
		add := func(expr ...any) {
			objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": n.NFTName, "chain": chain, "expr": expr, "comment": "server-connect:" + record.OperationID}})
		}
		add(match(map[string]any{"&": []any{meta("mark"), nativeTUNMarkMask}}, nativeTUNBypassMark), ret)
		add(match(map[string]any{"ct": map[string]any{"key": "direction"}}, "reply"), ret)
		add(match(meta("oif"), 1), ret)
		// Payload protocol names carry their family/transport dependencies.
		// nft removes redundant explicit meta checks when listing these rules.
		add(protected(4), ret)
		add(protected(6), ret)
		// Neighbor discovery must continue with a cold cache. These are
		// underlay-bound non-public controls, never a public ICMP exemption.
		payload := func(protocol, field string) any {
			return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
		}
		add(match(meta("oif"), n.UnderlayIndex), match(payload("ip6", "daddr"), map[string]any{"prefix": map[string]any{"addr": "ff02::", "len": 16}}), match(payload("icmpv6", "type"), map[string]any{"set": []any{133, 134, 135, 136}}), ret)
		add(match(meta("oif"), n.UnderlayIndex), match(payload("ip", "daddr"), "255.255.255.255"), match(payload("udp", "sport"), 68), match(payload("udp", "dport"), 67), ret)
		add(match(meta("oif"), n.UnderlayIndex), match(payload("ip", "daddr"), map[string]any{"prefix": map[string]any{"addr": "224.0.0.0", "len": 24}}), ret)
		for _, family := range []int{4, 6} {
			if nativeFamily(n, family).Address == "" {
				continue
			}
			nfproto := 2
			if family == 6 {
				nfproto = 10
			}
			expr := []any{match(meta("nfproto"), nfproto), match(meta("l4proto"), map[string]any{"set": []any{6, 17}})}
			if chain == "capture" {
				// OR forces these capture bits regardless of the AND input.
				// Include them in the AND mask to match nft's stable bitwise
				// delinearization while preserving every unrelated mark bit.
				expr = append(expr, map[string]any{"mangle": map[string]any{"key": meta("mark"), "value": map[string]any{"|": []any{map[string]any{"&": []any{meta("mark"), ^nativeTUNMarkMask | nativeTUNCaptureMark}}, nativeTUNCaptureMark}}}})
			} else {
				expr = append(expr, match(meta("oif"), n.LinkIndex), ret)
			}
			add(expr...)
		}
		if chain == "guard" {
			// Pinned Linux preserves the incoming device into POSTROUTING;
			// its absence is the local-origin sentinel. Forwarded traffic
			// must retain this chain's accept policy, including public flows.
			add(match(meta("iif"), 0), map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"drop": nil})
		}
	}
	return objects
}

func nativeNFTCreateJSON(record smartTUNTrialJournal) ([]byte, error) {
	commands := []any{}
	for i, object := range nativeNFTObjects(record) {
		verb := "add"
		if i == 0 {
			verb = "create"
		}
		commands = append(commands, map[string]any{verb: object})
	}
	return json.Marshal(map[string]any{"nftables": commands})
}
