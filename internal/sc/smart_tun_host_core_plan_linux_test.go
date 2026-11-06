//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testHostCoreWSProfile() Profile {
	return Profile{ID: "abcdef0123456789", Kind: "sing-box-json", Outbound: json.RawMessage(`{
  "type":"vless","tag":"upstream","server":"node.example.org","server_port":443,
  "uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247","tls":{"enabled":true,"server_name":"front.example.org"},
  "transport":{"type":"ws","path":"/example","headers":{"Host":"front.example.org"}}}`)}
}

func TestHostCoreAttachSelectedProfileNoRoutingOrDNS(t *testing.T) {
	profile := testHostCoreWSProfile()
	original := append([]byte(nil), profile.Outbound...)
	raw, err := compileHostCoreAttachConfig(profile, "8.8.8.8", "ens3", "sctunv70")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(original, profile.Outbound) {
		t.Fatal("compiler altered saved selected VPN credential")
	}
	var cfg struct {
		Inbounds []struct {
			Type         string   `json:"type"`
			Interface    string   `json:"interface_name"`
			Address      []string `json:"address"`
			AutoRoute    bool     `json:"auto_route"`
			AutoRedirect bool     `json:"auto_redirect"`
		} `json:"inbounds"`
		Outbounds []struct {
			Server      string `json:"server"`
			RoutingMark uint32 `json:"routing_mark"`
			TLS         struct {
				ServerName string `json:"server_name"`
			} `json:"tls"`
			Transport struct {
				Headers map[string]string `json:"headers"`
			} `json:"transport"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 1 || cfg.Inbounds[0].Interface != "sctunv70" || cfg.Inbounds[0].Type != "tun" ||
		len(cfg.Inbounds[0].Address) != 0 || cfg.Inbounds[0].AutoRoute || cfg.Inbounds[0].AutoRedirect ||
		len(cfg.Outbounds) != 2 || cfg.Outbounds[0].Server != "8.8.8.8" ||
		cfg.Outbounds[0].RoutingMark != nativeTUNBypassMark || cfg.Outbounds[0].TLS.ServerName != "front.example.org" ||
		cfg.Outbounds[0].Transport.Headers["Host"] != "front.example.org" {
		t.Fatalf("compiled core attach drifted from pinned non-routing operation")
	}
	if strings.Contains(string(raw), "auto_route\": true") || strings.Contains(string(raw), "hijack-dns") {
		t.Fatal("inert attach compiler enabled capture/DNS")
	}
	if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
		if err := CheckConfig(core, t.TempDir(), raw); err != nil {
			t.Fatalf("official sing-box rejected core-only attachment: %v", err)
		}
	}
}

func TestHostCoreAttachRejectsUnpinnedAmbiguousOrUntrustedSelectors(t *testing.T) {
	base := testHostCoreWSProfile()
	for _, tc := range []struct{ name, pin, mutate string }{
		{"bad pin", "127.0.0.1", ""},
		{"altered transport", "8.8.8.8", `"type":"grpc"`},
		{"no WebSocket Host", "8.8.8.8", `"headers":{}`},
		{"override routing mark", "8.8.8.8", `"routing_mark":123,`},
		{"restrict UDP", "8.8.8.8", `"network":"tcp",`},
		{"invalid packet encoding", "8.8.8.8", `"packet_encoding":"bad",`},
		{"implicit TLS authority", "8.8.8.8", `"server_name":""`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			if tc.mutate != "" {
				switch tc.name {
				case "altered transport":
					p.Outbound = bytes.Replace(p.Outbound, []byte(`"type":"ws"`), []byte(tc.mutate), 1)
				case "no WebSocket Host":
					p.Outbound = bytes.Replace(p.Outbound, []byte(`"headers":{"Host":"front.example.org"}`), []byte(tc.mutate), 1)
				case "override routing mark", "restrict UDP", "invalid packet encoding":
					p.Outbound = bytes.Replace(p.Outbound, []byte(`"tag":"upstream",`), []byte(`"tag":"upstream",`+tc.mutate), 1)
				case "implicit TLS authority":
					p.Outbound = bytes.Replace(p.Outbound, []byte(`"server_name":"front.example.org"`), []byte(tc.mutate), 1)
				}
			}
			if _, err := compileHostCoreAttachConfig(p, tc.pin, "ens3", "sctunv70"); err == nil {
				t.Fatal("unsafe native core attachment accepted")
			}
		})
	}
}
