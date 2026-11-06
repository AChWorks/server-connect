//go:build linux

package sc

// Narrow physical-host nft observation for the v9 development-only owner.
// V4's disconnected-fixture observer remains unchanged: never broaden it to
// silently adopt Docker NAT, raw NOTRACK, or an ingress marking rule. This
// explicitly recognizes only a fully verified already-owned ingress graph,
// the exact ip/ip6 raw paired NOTRACK grammar, and the independently proven
// Docker basic-bridge NAT grammar. All other packet-path writers fail closed.

import (
	"encoding/json"
	"strconv"
)

func hostRouteExactRawCT(fields map[string]any, ports map[uint16]bool) (string, bool) {
	family, ok := fields["family"].(string)
	if !ok || (family != "ip" && family != "ip6") || fields["table"] != "raw" || len(fields) != 5 {
		return "", false
	}
	chain, ok := fields["chain"].(string)
	if !ok || (chain != "PREROUTING" && chain != "OUTPUT") {
		return "", false
	}
	_, hasHandle := fields["handle"].(json.Number)
	if !hasHandle {
		return "", false
	}
	expr, ok := fields["expr"].([]any)
	if !ok || len(expr) != 3 {
		return "", false
	}
	matched, ok := expr[0].(map[string]any)
	if !ok || len(matched) != 1 {
		return "", false
	}
	match, ok := matched["match"].(map[string]any)
	if !ok || len(match) != 3 || match["op"] != "==" {
		return "", false
	}
	left, ok := match["left"].(map[string]any)
	if !ok || len(left) != 1 {
		return "", false
	}
	payload, ok := left["payload"].(map[string]any)
	if !ok || len(payload) != 2 || payload["protocol"] != "tcp" {
		return "", false
	}
	field := "dport"
	if chain == "OUTPUT" {
		field = "sport"
	}
	if payload["field"] != field {
		return "", false
	}
	number, ok := match["right"].(json.Number)
	if !ok {
		return "", false
	}
	port, err := strconv.ParseUint(number.String(), 10, 16)
	if err != nil || port == 0 || !ports[uint16(port)] {
		return "", false
	}
	counter, ok := expr[1].(map[string]any)
	if !ok || len(counter) != 1 {
		return "", false
	}
	counts, ok := counter["counter"].(map[string]any)
	if !ok || len(counts) != 2 {
		return "", false
	}
	for _, field := range []string{"packets", "bytes"} {
		v, ok := counts[field].(json.Number)
		if !ok {
			return "", false
		}
		if _, err := strconv.ParseUint(v.String(), 10, 64); err != nil {
			return "", false
		}
	}
	xt, ok := expr[2].(map[string]any)
	if !ok || len(xt) != 1 {
		return "", false
	}
	target, ok := xt["xt"].(map[string]any)
	if !ok || len(target) != 2 || target["type"] != "target" || target["name"] != "CT" {
		return "", false
	}
	return family + ":" + chain + ":" + number.String(), true
}

// Verify raw table and chain headers as strictly as their packet actions.
// An nft-native extension that iptables -S cannot describe is not an allowed
// extra foreign owner, even when its table happens to be named raw.
func hostRouteExactRawHeader(kind string, fields map[string]any) (string, bool) {
	family, _ := fields["family"].(string)
	if family != "ip" && family != "ip6" {
		return "", false
	}
	number, ok := fields["handle"].(json.Number)
	if !ok {
		return "", false
	}
	handle, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || handle == 0 {
		return "", false
	}
	if kind == "table" {
		if len(fields) != 3 || fields["name"] != "raw" {
			return "", false
		}
		return family + ":table", true
	}
	if kind != "chain" || len(fields) != 8 || fields["table"] != "raw" ||
		fields["type"] != "filter" || fields["policy"] != "accept" {
		return "", false
	}
	name, _ := fields["name"].(string)
	hook := "prerouting"
	if name == "OUTPUT" {
		hook = "output"
	} else if name != "PREROUTING" {
		return "", false
	}
	if fields["hook"] != hook {
		return "", false
	}
	priority, ok := fields["prio"].(json.Number)
	if !ok || priority.String() != "-300" {
		return "", false
	}
	return family + ":" + name, true
}

func hostRouteNFTFilter(objects []map[string]any, record smartTUNTrialJournal, ingress hostIngressStage, ports map[uint16]bool, docker bool) ([]map[string]any, error) {
	refuse := func() ([]map[string]any, error) {
		return nil, Fault("trial_resource_conflict", "unsupported or changed foreign packet-path nft effects during routed policy")
	}
	if len(ports) == 0 || len(ports) > 128 {
		return refuse()
	}
	seenRaw := map[string]bool{}
	seenHeaders := map[string]bool{}
	remaining := make([]map[string]any, 0, len(objects))
	for _, item := range objects {
		if len(item) != 1 {
			return refuse()
		}
		for kind, value := range item {
			fields, ok := value.(map[string]any)
			if !ok {
				return refuse()
			}
			family, _ := fields["family"].(string)
			table, _ := fields["table"].(string)
			name, _ := fields["name"].(string)
			if kind == "table" {
				table = name
			}
			if family == "inet" && table == "scin_"+ingress.OperationID {
				// A complete, stable same-operation graph is checked by the caller.
				continue
			}
			if family == "inet" && table == record.Native.NFTName {
				remaining = append(remaining, item)
				continue
			}
			if family == "ip" && table == "nat" {
				if !docker {
					return refuse()
				}
				continue // Only exact Docker NAT snapshot may be stripped.
			}
			if (family == "ip" || family == "ip6") && table == "raw" {
				if kind != "rule" {
					key, ok := hostRouteExactRawHeader(kind, fields)
					if !ok || seenHeaders[key] {
						return refuse()
					}
					seenHeaders[key] = true
					continue
				}
				key, ok := hostRouteExactRawCT(fields, ports)
				if !ok || seenRaw[key] {
					return refuse()
				}
				seenRaw[key] = true
				continue
			}
			if kind == "flowtable" || (kind == "rule" && !nativeNFTForeignRulePassive(fields)) || nativeNFTForeignConflict(fields, record) {
				return refuse()
			}
			remaining = append(remaining, item)
		}
	}
	for _, family := range []string{"ip", "ip6"} {
		for _, key := range []string{":table", ":PREROUTING", ":OUTPUT"} {
			if !seenHeaders[family+key] {
				return refuse()
			}
		}
	}
	for port := range ports {
		for _, family := range []string{"ip", "ip6"} {
			for _, chain := range []string{"PREROUTING", "OUTPUT"} {
				key := family + ":" + chain + ":" + strconv.FormatUint(uint64(port), 10)
				if !seenRaw[key] {
					return refuse()
				}
			}
		}
	}
	return remaining, nil
}

// Callback captures an exact parent under the uninterrupted activation flock.
// Its native record argument must be identical to that parent; a stale caller
// cannot use changed ingress/Core state as observation or deletion authority.
func hostRouteNFTObserver(r *hostRouteJournal) func(smartTUNTrialJournal) (nativeTUNNFTObservation, error) {
	return func(record smartTUNTrialJournal) (nativeTUNNFTObservation, error) {
		if r == nil || !sameSmartTUNTrial(r.nativeView(), record) {
			return nativeTUNNFTObservation{}, Fault("activation_journal_conflict", "host policy native observation parent changed")
		}
		ingress := r.Progress.Ingress
		if ingress.NFTStage != "observed" || ingress.NFTHandle == 0 || ingress.RawSHA256 == "" ||
			r.Progress.Barrier.Stage != "closed" || ingress.Phase != "pending" {
			return nativeTUNNFTObservation{}, Fault("trial_recovery_uncertain", "host ingress/barrier not receipted for native policy")
		}
		if err := hostIngressNamespace(ingress); err != nil {
			return nativeTUNNFTObservation{}, err
		}
		for attempt := 0; attempt < 3; attempt++ {
			interfacesBefore, err := nativeNFTObserveInterfaces(record)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			before, err := nativeNFTGeneration()
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			ports, digest, err := hostIngressRawSnapshot()
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			if digest != ingress.RawSHA256 {
				return nativeTUNNFTObservation{}, Fault("trial_resource_conflict", "host raw NOTRACK owner changed during routed policy")
			}
			after, err := nativeNFTGeneration()
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			interfacesAfter, err := nativeNFTObserveInterfaces(record)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			if before == 0 || before != after || !nativeNFTSameInterfaces(interfacesBefore, interfacesAfter) {
				continue
			}
			objects, err := nativeTUNNftObjects(raw)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			evidence, err := hostIngressNFTFromRowsWithRenderer(ingress, objects, after, hostIngressLegacyMissingTableComment(raw))
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			if !evidence.Present || !evidence.Matches || evidence.Handle != ingress.NFTHandle || evidence.SHA256 != ingress.NFTSHA256 {
				return nativeTUNNFTObservation{}, Fault("trial_resource_conflict", "host ingress nft owner changed during routed policy")
			}
			if err := hostIngressForeignNATBoundary(ingress, objects); err != nil {
				return nativeTUNNFTObservation{}, err
			}
			profile, err := generalHostForeignNFTEffects(objects)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			filtered, err := hostRouteNFTFilter(objects, record, ingress, ports, profile.ForeignNAT)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			// Check only foreign rules. scnt belongs to this journal and its
			// mark/mangle effects are verified separately by the native receipt.
			foreign := make([]map[string]any, 0, len(filtered))
			for _, item := range filtered {
				for kind, value := range item {
					fields := value.(map[string]any)
					name, _ := fields["table"].(string)
					if kind == "table" {
						name, _ = fields["name"].(string)
					}
					if fields["family"] == "inet" && name == record.Native.NFTName {
						continue
					}
					foreign = append(foreign, item)
				}
			}
			if err := hostIngressForeignNFTBoundary(ingress, record, foreign); err != nil {
				return nativeTUNNFTObservation{}, err
			}
			if err := nativeNFTPinInterfaces(filtered, interfacesAfter); err != nil {
				return nativeTUNNFTObservation{}, err
			}
			return nativeTUNNFTFromRows(filtered, record, after)
		}
		return nativeTUNNFTObservation{}, Fault("trial_recovery_uncertain", "host-routed nft/links changed during bounded ownership observation")
	}
}
