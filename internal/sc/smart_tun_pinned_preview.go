package sc

import (
	"encoding/json"
	"net/netip"
	"strings"
)

// projectPinnedVLESSNativePreview compiles an isolated copy of a selected
// outbound against an operator-supplied public IPv4. This is NOT DNS/underlay
// evidence, an activation reservation, or authority for privileged Apply.
//
// Only plain TCP transport is supported: pinning the dial address of a
// WebSocket/HTTP transport may change its implicit HTTP Host header.
func projectPinnedVLESSNativePreview(profile Profile, rawPin string) (Profile, error) {
	refused := func() (Profile, error) {
		return Profile{}, Fault("trial_unsupported", "pinned VLESS preview requires a supported unambiguous TCP outbound and public IPv4 pin")
	}
	pin, err := netip.ParseAddr(rawPin)
	if err != nil || !pin.Is4() || !pin.IsGlobalUnicast() ||
		pin.IsPrivate() || pin.IsLoopback() || pin.IsLinkLocalUnicast() ||
		overlapsSpecialPurpose(netip.PrefixFrom(pin, 32)) {
		return refused()
	}
	if err := rejectAmbiguousJournalJSON(profile.Outbound); err != nil {
		return refused()
	}
	kind, hostname, transport, _, err := selectedSmartTUNHostEndpoint(profile, pin)
	if err != nil || transport != "tcp" {
		return refused()
	}
	if kind == "ipv4" {
		// An already literal endpoint must match the explicit pin.
		return profile, nil
	}
	if kind != "hostname" || hostname == "" {
		return refused()
	}
	var outbound map[string]json.RawMessage
	if json.Unmarshal(profile.Outbound, &outbound) != nil || outbound == nil {
		return refused()
	}
	if raw, ok := outbound["tls"]; ok {
		var tlsFields map[string]json.RawMessage
		if json.Unmarshal(raw, &tlsFields) != nil || tlsFields == nil {
			return refused()
		}
		var enabled bool
		if json.Unmarshal(tlsFields["enabled"], &enabled) != nil || !enabled {
			// Avoid inferring an unknown TLS state from an imported outbound.
			return refused()
		}
		var serverName string
		if rawName, present := tlsFields["server_name"]; present {
			if json.Unmarshal(rawName, &serverName) != nil ||
				strings.TrimSpace(serverName) != serverName {
				return refused()
			}
		}
		if serverName == "" {
			// Replacing the hostname must not silently invent a TLS/SNI
			// identity. Require the selected profile's explicit server_name.
			return refused()
		}
		outbound["tls"], err = json.Marshal(tlsFields)
		if err != nil {
			return refused()
		}
	}
	outbound["server"], _ = json.Marshal(pin.String())
	projectedBytes, err := json.Marshal(outbound)
	if err != nil {
		return refused()
	}
	projected := profile
	projected.Outbound = projectedBytes
	return projected, nil // Never modifies the stored selected profile.
}
