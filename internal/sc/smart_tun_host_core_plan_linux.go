//go:build linux

package sc

// Core-only (no captured application traffic) official sing-box 1.14
// configuration. It attaches to the already receipted persistent native TUN
// while all host FIB/RPDB/nft egress capture and DNS remain untouched. It is
// NOT an activation config; another reviewed parent stage must own policy.

import (
	"encoding/json"
	"net/netip"
)

func compileHostCoreAttachConfig(profile Profile, pinnedIP, underlay, tunnel string) ([]byte, error) {
	refuse := func() ([]byte, error) {
		return nil, Fault("trial_unsupported", "host core attach requires a pinned VLESS TLS WebSocket profile and a non-routing TUN")
	}
	if !idPattern.MatchString(profile.ID) || !smartTUNDeviceName.MatchString(tunnel) ||
		!smartTUNDeviceName.MatchString(underlay) || tunnel == underlay || tunnel == "lo" || underlay == "lo" {
		return refuse()
	}
	ip, err := netip.ParseAddr(pinnedIP)
	if err != nil || !ip.Is4() {
		return refuse()
	}
	_, _, transport, _, err := selectedSmartTUNHostEndpoint(profile, ip)
	if err != nil || transport != "ws" {
		return refuse()
	}
	projected, err := projectPinnedVLESSNativePreview(profile, pinnedIP)
	if err != nil {
		return refuse()
	}
	if err := rejectAmbiguousJournalJSON(projected.Outbound); err != nil {
		return refuse()
	}
	var outbound map[string]json.RawMessage
	if json.Unmarshal(projected.Outbound, &outbound) != nil || outbound == nil {
		return refuse()
	}
	allow := map[string]bool{"type": true, "tag": true, "server": true, "server_port": true, "uuid": true,
		"flow": true, "tls": true, "transport": true, "packet_encoding": true}
	for key := range outbound {
		if !allow[key] {
			return refuse()
		}
	}
	var tag, typ, server string
	if json.Unmarshal(outbound["tag"], &tag) != nil || tag != "upstream" ||
		json.Unmarshal(outbound["type"], &typ) != nil || typ != "vless" ||
		json.Unmarshal(outbound["server"], &server) != nil || server != pinnedIP {
		return refuse()
	}
	var tls struct {
		Enabled    bool   `json:"enabled"`
		ServerName string `json:"server_name"`
	}
	if json.Unmarshal(outbound["tls"], &tls) != nil || !tls.Enabled || tls.ServerName == "" {
		return refuse()
	}
	var ws struct {
		Type    string                     `json:"type"`
		Headers map[string]json.RawMessage `json:"headers"`
	}
	if json.Unmarshal(outbound["transport"], &ws) != nil || ws.Type != "ws" || ws.Headers == nil {
		return refuse()
	}
	var host string
	if json.Unmarshal(ws.Headers["Host"], &host) != nil || host != tls.ServerName {
		return refuse()
	}
	if raw, ok := outbound["packet_encoding"]; ok {
		var mode string
		if json.Unmarshal(raw, &mode) != nil || (mode != "" && mode != "xudp" && mode != "packetaddr") {
			return refuse()
		}
	}
	outbound["routing_mark"], _ = json.Marshal(nativeTUNBypassMark)
	// The persistent TUN is not given any routing authority by the sing-box
	// unit. The kernel policy stage is separate and remains absent here.
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "interface_name": tunnel,
			"address": []string{}, "mtu": 1400, "stack": "gvisor", "auto_route": false, "auto_redirect": false}},
		"outbounds": []any{outbound, map[string]any{"type": "direct", "tag": "direct", "routing_mark": nativeTUNBypassMark}},
		"route":     map[string]any{"final": "upstream", "default_mark": nativeTUNBypassMark},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return refuse()
	}
	return raw, nil
}
