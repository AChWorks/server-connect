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
// Plain TCP and an explicit, identity-pinned WebSocket Host+TLS pairing are
// supported. Other transports or implicit HTTP Host defaults must fail
// closed: replacing a hostname with an IP could otherwise change the wire
// HTTP authority even if the TLS SNI remains constant.
func projectPinnedVLESSNativePreview(profile Profile, rawPin string) (Profile, error) {
	refused := func() (Profile, error) {
		return Profile{}, Fault("trial_unsupported", "pinned VLESS preview requires a supported TCP/explicit-Host WebSocket outbound and public IPv4 pin")
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
	if err != nil || (transport != "tcp" && transport != "ws") {
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
	var tlsServerName string
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
		// A nonempty, unpadded string is not necessarily a valid TLS identity.
		// Reuse the strict DNS-name grammar, while separately admitting plain
		// IP identities (never scoped IPv6 or IPv4-mapped IPv6). Keep the
		// original value unchanged; no inferred SNI or normalization.
		if address, parseErr := netip.ParseAddr(serverName); parseErr == nil {
			if address.Zone() != "" || address.Is4In6() {
				return refused()
			}
		} else if _, nameErr := validateEndpointHostname(serverName); nameErr != nil {
			return refused()
		}
		tlsServerName = serverName
		// The checked TLS object is already a pinned raw JSON value. Do not
		// unnecessarily reserialize or normalize any TLS configuration.
	}
	if transport == "ws" {
		// The pinned dial IP is permitted ONLY if sing-box will continue to
		// send the original explicit, unambiguous HTTP Host and TLS SNI.
		// A missing Host would make the WebSocket client derive it from the
		// newly pinned numeric destination. Duplicate/case-variant Host names
		// can make request authority ambiguous even when JSON itself parses.
		if tlsServerName == "" {
			return refused()
		}
		var ws struct {
			Type    string                     `json:"type"`
			Headers map[string]json.RawMessage `json:"headers"`
		}
		if json.Unmarshal(outbound["transport"], &ws) != nil || ws.Type != "ws" ||
			ws.Headers == nil || len(ws.Headers) == 0 {
			return refused()
		}
		for name := range ws.Headers {
			if strings.EqualFold(name, "Host") && name != "Host" {
				return refused()
			}
		}
		var host string
		if json.Unmarshal(ws.Headers["Host"], &host) != nil || host != tlsServerName {
			return refused()
		}
		// Neither Host nor transport, headers, paths or TLS identity are
		// modified by the projection; only the upstream socket dial IP is.
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
