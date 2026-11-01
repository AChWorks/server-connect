package sc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const CoreVersion = "1.14.3"
const MaxProfileBytes = 1024 * 1024

var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Profile contains only a selected remote outbound. Incoming routes, DNS, and
// system networking settings from an imported config are never adopted.
type Profile struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Kind     string          `json:"kind"`
	Outbound json.RawMessage `json:"outbound"`
	Created  string          `json:"created"`
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ValidateSource(input []byte, tag string) (Profile, error) {
	input = bytes.TrimSpace(input)
	if len(input) == 0 || len(input) > MaxProfileBytes {
		return Profile{}, errors.New("profile input is empty or exceeds 1 MiB")
	}
	var outbound json.RawMessage
	var kind, name string
	if bytes.HasPrefix(input, []byte("vless://")) {
		var err error
		outbound, name, err = parseVLESS(string(input))
		if err != nil {
			return Profile{}, err
		}
		kind = "vless-link"
	} else {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(input, &doc); err != nil {
			return Profile{}, errors.New("invalid JSON config")
		}
		candidates := []json.RawMessage{}
		if raw, ok := doc["outbounds"]; ok {
			if err := json.Unmarshal(raw, &candidates); err != nil {
				return Profile{}, errors.New("outbounds must be an array")
			}
		} else if _, ok := doc["type"]; ok {
			candidates = append(candidates, input)
		} else {
			return Profile{}, errors.New("expected sing-box config with outbounds or a single outbound")
		}
		eligible := []json.RawMessage{}
		for _, candidate := range candidates {
			var fields map[string]json.RawMessage
			if json.Unmarshal(candidate, &fields) != nil {
				return Profile{}, errors.New("invalid outbound entry")
			}
			var typ, candidateTag string
			_ = json.Unmarshal(fields["type"], &typ)
			_ = json.Unmarshal(fields["tag"], &candidateTag)
			switch typ {
			case "vless", "vmess", "trojan", "shadowsocks", "hysteria2":
				if tag == "" || tag == candidateTag {
					eligible = append(eligible, candidate)
				}
			}
		}
		if len(eligible) != 1 {
			return Profile{}, errors.New("exactly one supported remote outbound must match; use --tag when there are multiple")
		}
		outbound = eligible[0]
		name = "Imported outbound"
		kind = "sing-box-json"
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(outbound, &fields); err != nil {
		return Profile{}, errors.New("invalid outbound")
	}
	delete(fields, "tag")
	fields["tag"] = json.RawMessage(`"upstream"`)
	outbound, _ = json.Marshal(fields)
	id, err := randomHex(8)
	if err != nil {
		return Profile{}, err
	}
	return Profile{ID: id, Name: name, Kind: kind, Outbound: outbound, Created: time.Now().UTC().Format(time.RFC3339)}, nil
}

func parseVLESS(raw string) (json.RawMessage, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "vless" || u.User == nil {
		return nil, "", errors.New("invalid VLESS link")
	}
	uuid := u.User.Username()
	if !uuidPattern.MatchString(uuid) {
		return nil, "", errors.New("invalid VLESS UUID")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return nil, "", errors.New("unexpected VLESS password segment")
	}
	host := u.Hostname()
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || host == "" || strings.ContainsAny(host, "\r\n\t ") {
		return nil, "", errors.New("invalid VLESS endpoint or port")
	}
	if net.ParseIP(host) == nil && len(host) > 253 {
		return nil, "", errors.New("endpoint hostname too long")
	}
	// URL.Query discards malformed pairs without an error. A dropped TLS or
	// transport option could silently change the wire security of a link.
	// ParseQuery also tolerates empty components and bare keys; treat those as
	// ambiguous instead of silently applying TCP or security defaults.
	if u.RawQuery != "" {
		for _, pair := range strings.Split(u.RawQuery, "&") {
			if pair == "" || !strings.Contains(pair, "=") {
				return nil, "", Fault("unsupported_profile", "malformed VLESS query")
			}
		}
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, "", Fault("unsupported_profile", "malformed VLESS query")
	}
	allowed := map[string]bool{
		"type": true, "security": true, "encryption": true, "flow": true,
		"sni": true, "fp": true, "alpn": true, "pbk": true, "sid": true,
		"path": true, "host": true, "headerType": true,
	}
	for name, values := range q {
		if !allowed[name] || len(values) != 1 {
			return nil, "", Fault("unsupported_profile", "unknown, repeated or unsupported VLESS query option")
		}
	}
	typ := q.Get("type")
	if typ == "" {
		typ = "tcp"
	}
	if typ != "tcp" && typ != "ws" && typ != "httpupgrade" {
		return nil, "", Fault("unsupported_profile", "unsupported VLESS transport")
	}
	// Xray share links often include headerType even on transports where
	// it is inert. Never interpret TCP HTTP-header camouflage as plain TCP:
	// sing-box's HTTPUpgrade is a different wire protocol.
	if header := q.Get("headerType"); header != "" && header != "none" {
		return nil, "", Fault("unsupported_profile", "unsupported VLESS TCP header camouflage")
	}
	security := q.Get("security")
	if security == "" {
		security = "none"
	}
	if security != "none" && security != "tls" && security != "reality" {
		return nil, "", Fault("unsupported_profile", "unsupported VLESS security")
	}
	// Xray's REALITY compatibility matrix excludes WebSocket/HTTPUpgrade.
	// A syntactically valid sing-box outbound does not imply server support.
	if security == "reality" && typ != "tcp" {
		return nil, "", Fault("unsupported_profile", "REALITY requires plain TCP transport")
	}
	if (typ == "ws" || typ == "httpupgrade") && q.Get("path") != "" {
		if err := rejectXrayEarlyDataPath(q.Get("path")); err != nil {
			return nil, "", err
		}
	}
	if typ == "tcp" {
		// Xray's path does not apply to TCP with explicitly disabled header
		// camouflage. Keep accepting old empty metadata; refuse meaningful
		// transport fields unless the source explicitly declares plain TCP.
		if q.Get("host") != "" || (q.Get("path") != "" && q.Get("headerType") != "none") {
			return nil, "", Fault("unsupported_profile", "HTTP transport fields require WebSocket or HTTPUpgrade")
		}
	}
	if security == "none" && (q.Has("sni") || q.Has("fp") || q.Has("alpn") || q.Has("pbk") || q.Has("sid")) {
		return nil, "", Fault("unsupported_profile", "TLS-specific options require TLS or Reality")
	}
	if security != "reality" && (q.Has("pbk") || q.Has("sid")) {
		return nil, "", Fault("unsupported_profile", "Reality-specific options require Reality")
	}
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return nil, "", errors.New("unsupported VLESS encryption")
	}
	if q.Get("flow") != "" && q.Get("flow") != "xtls-rprx-vision" {
		return nil, "", errors.New("unsupported VLESS flow")
	}
	if typ != "tcp" && q.Get("flow") != "" {
		return nil, "", errors.New("VLESS HTTP transport with vision flow is unsupported")
	}
	if security == "none" && q.Get("flow") != "" {
		return nil, "", errors.New("vision flow requires TLS")
	}
	ob := map[string]any{"type": "vless", "tag": "upstream", "server": host, "server_port": port, "uuid": uuid}
	if q.Get("flow") != "" {
		ob["flow"] = q.Get("flow")
	}
	if typ == "ws" || typ == "httpupgrade" {
		transport := map[string]any{"type": typ, "path": "/"}
		if q.Get("path") != "" {
			transport["path"] = q.Get("path")
		}
		if q.Get("host") != "" {
			if typ == "ws" {
				transport["headers"] = map[string]string{"Host": q.Get("host")}
			} else {
				transport["host"] = q.Get("host")
			}
		}
		ob["transport"] = transport
	}
	if security != "none" {
		sni := q.Get("sni")
		if sni == "" {
			sni = host
		}
		tls := map[string]any{"enabled": true, "server_name": sni}
		if fp := q.Get("fp"); fp != "" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
		}
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		if security == "reality" {
			if q.Get("fp") == "" {
				return nil, "", Fault("unsupported_profile", "Reality clients require a supported uTLS fingerprint (fp)")
			}
			if q.Get("pbk") == "" || q.Get("sni") == "" {
				return nil, "", errors.New("Reality requires pbk and sni")
			}
			tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		}
		ob["tls"] = tls
	}
	b, _ := json.Marshal(ob)
	name := strings.TrimSpace(u.Fragment)
	if name == "" {
		name = "VLESS profile"
	}
	if len(name) > 80 {
		name = name[:80]
	}
	name = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, name)
	return b, name, nil
}

// Xray interprets an `ed` query parameter inside the HTTP transport path as
// early-data handshake configuration. Passing it through as a literal sing-box
// path silently changes the protocol (sing-box WS has separate settings;
// HTTPUpgrade has no equivalent). Until equivalent wire behavior is proved,
// reject such links; preserve all unrelated path queries byte-for-byte.
func rejectXrayEarlyDataPath(path string) error {
	_, rawQuery, found := strings.Cut(path, "?")
	if !found {
		return nil
	}
	options, err := url.ParseQuery(rawQuery)
	if err != nil {
		return Fault("unsupported_profile", "malformed VLESS HTTP transport path query")
	}
	if _, found := options["ed"]; found {
		return Fault("unsupported_profile", "Xray HTTP transport Early Data is unsupported")
	}
	return nil
}

func CoreConfig(p Profile, port int, password string) ([]byte, error) {
	if port < 1024 || port > 65535 {
		return nil, errors.New("local port must be between 1024 and 65535")
	}
	if password == "" {
		return nil, errors.New("local proxy authentication is required")
	}
	cfg := map[string]any{
		"log":       map[string]any{"level": "warn"},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": port, "users": []any{map[string]string{"username": "sc", "password": password}}}},
		"outbounds": []any{json.RawMessage(p.Outbound)},
		"route":     map[string]any{"final": "upstream"},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func CheckConfig(core, base string, config []byte) error {
	f, err := os.CreateTemp(base, ".validate-*.json")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(config)
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "check", "-c", path)
	if e := cmd.Run(); e != nil {
		if ctx.Err() != nil {
			return Fault("core_timeout", "sing-box core validation timed out")
		}
		return Fault("core_config_rejected", "sing-box rejected the profile; check supported fields and transport")
	}
	return nil
}

func EnsureCore(core string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, core, "version").Output()
	if e != nil {
		return Fault("core_unavailable", "pinned sing-box core unavailable or not executable")
	}
	if !strings.HasPrefix(string(b), "sing-box version "+CoreVersion+"\n") {
		return Fault("core_version_mismatch", "pinned sing-box core version mismatch")
	}
	return nil
}

func SecretConfigTemp(root string, cfg []byte) (string, error) {
	f, err := os.CreateTemp(root, ".core-check-*.json")
	if err != nil {
		return "", err
	}
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	if _, err = f.Write(cfg); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return filepath.Clean(f.Name()), nil
}
