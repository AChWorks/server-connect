package sc

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func pinnedPreviewNamedProfile(tlsObject string) Profile {
	tls := ""
	if tlsObject != "" {
		tls = `,"tls":` + tlsObject
	}
	return Profile{ID: "private-selected-id", Kind: "vless-link", Outbound: json.RawMessage(
		`{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"uuid":"c2902f3a-1c25-41ef-a8dc-760b483aa247"` + tls + `}`)}
}

func TestPinnedVLESSNativePreviewKeepsOriginalAndTLSIdentity(t *testing.T) {
	for _, tc := range []struct{ name, tls, expectedName string }{
		{"explicit TLS name", `{"enabled":true,"server_name":"front.example.net","alpn":["h2"]}`, "front.example.net"},
		{"mixed-case DNS identity", `{"enabled":true,"server_name":"Front.Example.Net"}`, "Front.Example.Net"},
		{"IPv4 TLS identity", `{"enabled":true,"server_name":"198.51.100.42"}`, "198.51.100.42"},
		{"IPv6 TLS identity", `{"enabled":true,"server_name":"2001:db8::42"}`, "2001:db8::42"},
		{"raw TCP", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := pinnedPreviewNamedProfile(tc.tls)
			original := append([]byte(nil), profile.Outbound...)
			projected, err := projectPinnedVLESSNativePreview(profile, "8.8.8.8")
			if err != nil {
				t.Fatal(err)
			}
			if projected.ID != profile.ID || !bytes.Equal(profile.Outbound, original) ||
				bytes.Equal(projected.Outbound, profile.Outbound) {
				t.Fatal("stored profile mutated, identity changed or pin not applied")
			}
			var outbound struct {
				Server string `json:"server"`
				UUID   string `json:"uuid"`
				TLS    struct {
					ServerName string   `json:"server_name"`
					ALPN       []string `json:"alpn"`
				} `json:"tls"`
			}
			if err := json.Unmarshal(projected.Outbound, &outbound); err != nil {
				t.Fatal(err)
			}
			if outbound.Server != "8.8.8.8" ||
				outbound.UUID != "c2902f3a-1c25-41ef-a8dc-760b483aa247" ||
				outbound.TLS.ServerName != tc.expectedName {
				t.Fatalf("unsafe dial projection or TLS name drift: %+v", outbound)
			}
			if strings.Contains(tc.tls, `"alpn"`) {
				if len(outbound.TLS.ALPN) != 1 || outbound.TLS.ALPN[0] != "h2" {
					t.Fatalf("TLS ALPN unexpectedly changed: %+v", outbound)
				}
			} else if len(outbound.TLS.ALPN) != 0 {
				t.Fatalf("TLS ALPN was invented during projection: %+v", outbound)
			}
			_, opts := smartTUNFixture()
			if _, err := smartTUNNativeConfig(profile, opts); err == nil {
				t.Fatal("unprojected named outbound bypassed native admission")
			}
			config, err := smartTUNNativeConfig(projected, opts)
			if err != nil {
				t.Fatalf("native config rejected pinned projection: %v", err)
			}
			if len(config) == 0 || !bytes.Contains(config, []byte(`"server": "8.8.8.8"`)) {
				t.Fatal("native policy did not use the exact projected IPv4 pin")
			}
			if core := os.Getenv("SC_TEST_SINGBOX"); core != "" {
				if err := CheckConfig(core, t.TempDir(), config); err != nil {
					t.Fatalf("real pinned sing-box refused compiled policy: %v", err)
				}
			}
			again, err := projectPinnedVLESSNativePreview(profile, "8.8.8.8")
			if err != nil || !bytes.Equal(projected.Outbound, again.Outbound) {
				t.Fatal("pinned projection was not deterministic")
			}
		})
	}
}

// These values are nonempty and unpadded, yet are not admissible TLS host
// identities. In particular, Go's JSON parser accepts escaped NUL/control
// characters, and trimming does not detect embedded whitespace.
func TestPinnedVLESSNativePreviewRejectsMalformedTLSIdentityWithoutMutation(t *testing.T) {
	for _, tc := range []struct{ name, jsonName string }{
		{"embedded space", `"bad name.example"`},
		{"embedded NUL", `"bad\u0000name.example"`},
		{"embedded tab", `"bad\tname.example"`},
		{"embedded newline", `"bad\nname.example"`},
		{"leading hyphen", `"-bad.example.net"`},
		{"trailing hyphen", `"bad-.example.net"`},
		{"empty label", `"bad..example.net"`},
		{"single label", `"localhost"`},
		{"oversized label", `"` + strings.Repeat("a", 64) + `.example.net"`},
		{"oversized hostname", `"` + strings.Repeat("a.", 128) + `example.net"`},
		{"non-ASCII label", `"é.example.net"`},
		{"scoped IPv6 identity", `"fe80::1%eth0"`},
		{"IPv4-mapped IPv6 identity", `"::ffff:192.0.2.1"`},
		{"malformed IPv6 identity", `"2001:db8:::1"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := pinnedPreviewNamedProfile(`{"enabled":true,"server_name":` + tc.jsonName + `}`)
			before := append([]byte(nil), profile.Outbound...)
			if _, err := projectPinnedVLESSNativePreview(profile, "8.8.8.8"); err == nil {
				t.Fatalf("invalid TLS server_name %s admitted", tc.name)
			}
			if !bytes.Equal(before, profile.Outbound) {
				t.Fatal("rejected TLS identity mutated selected profile")
			}
		})
	}
}

func TestPinnedVLESSNativePreviewRejectsUntrustedOrDriftingInput(t *testing.T) {
	base := pinnedPreviewNamedProfile(`{"enabled":true}`)
	for _, pin := range []string{"", "not-an-ip", "127.0.0.1", "10.0.0.8", "192.0.2.1", "224.0.0.1", "2001:4860:4860::8888", "8.8.8.8/32"} {
		t.Run("pin "+pin, func(t *testing.T) {
			if _, err := projectPinnedVLESSNativePreview(base, pin); err == nil {
				t.Fatalf("unsafe/unparseable explicit pin %q accepted", pin)
			}
		})
	}
	for _, tc := range []struct{ name, raw string }{
		{"wrong literal", `{"type":"vless","tag":"upstream","server":"1.1.1.1","server_port":443,"uuid":"SECRET"}`},
		{"not VLESS", `{"type":"trojan","tag":"upstream","server":"node.example.org","server_port":443}`},
		{"websocket implicit host", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"transport":{"type":"ws"}}`},
		{"httpupgrade implicit host", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"transport":{"type":"httpupgrade"}}`},
		{"foreign dial selector", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"detour":"other"}`},
		{"bad hostname", `{"type":"vless","tag":"upstream","server":"not_a_host","server_port":443}`},
		{"disabled TLS", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":false}}`},
		{"missing TLS enabled", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"server_name":"front.example.net"}}`},
		{"implicit TLS server name", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":true}}`},
		{"empty TLS server name", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":true,"server_name":""}}`},
		{"bad TLS type", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":true}`},
		{"bad TLS SNI type", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":true,"server_name":42}}`},
		{"space-padded TLS SNI", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":true,"server_name":" front.example.net "}}`},
		{"duplicate server", `{"type":"vless","tag":"upstream","server":"node.example.org","server":"node.example.net","server_port":443}`},
		{"duplicate nested TLS", `{"type":"vless","tag":"upstream","server":"node.example.org","server_port":443,"tls":{"enabled":true,"enabled":false}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Profile{Outbound: json.RawMessage(tc.raw)}
			if _, err := projectPinnedVLESSNativePreview(p, "8.8.8.8"); err == nil {
				t.Fatalf("untrusted selected profile %s admitted", tc.name)
			}
		})
	}
	literal := Profile{Outbound: json.RawMessage(`{"type":"vless","tag":"upstream","server":"8.8.8.8","server_port":443,"uuid":"KEEP"}`)}
	got, err := projectPinnedVLESSNativePreview(literal, "8.8.8.8")
	if err != nil || !bytes.Equal(got.Outbound, literal.Outbound) {
		t.Fatalf("matching literal pin unexpectedly changed selected profile: %v", err)
	}
	if _, err := projectPinnedVLESSNativePreview(base, strings.Repeat("8", 300)); err == nil {
		t.Fatal("oversized pin accepted")
	}
}

// The host-readiness selector is shared with compile-only native projection.
// A standalone alias must not make the in-memory preview claim a supported
// wire identity or mutate the source profile.
func TestPinnedVLESSNativePreviewRejectsNoncanonicalSelectedKeysWithoutMutation(t *testing.T) {
	for _, outbound := range []string{
		`{"type":"vless","server":"node.example.org","server_port":443,"Bind_Interface":"tun0"}`,
		`{"type":"vless","\u017ferver":"node.example.org","server_port":443}`,
		`{"type":"vless","server":"node.example.org","server_port":443,"tls":{"enabled":true,"Server_Name":"front.example.net"}}`,
		`{"type":"vless","server":"node.example.org","server_port":443,"tls":{"enabled":true,"utls":{"Fingerprint":"chrome"}}}`,
		`{"type":"vless","server":"node.example.org","server_port":443,"server":"node.example.org","\u017ferver":"other.example.org"}`,
	} {
		p := Profile{Outbound: json.RawMessage(outbound)}
		before := append([]byte(nil), p.Outbound...)
		if _, err := projectPinnedVLESSNativePreview(p, "8.8.8.8"); err == nil ||
			!bytes.Equal(p.Outbound, before) {
			t.Fatal("noncanonical preview input was admitted or mutated the source")
		}
	}
}
