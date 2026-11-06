//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func dockerNATFixture() (json.RawMessage, json.RawMessage, json.RawMessage, []map[string]any, []byte, []byte) {
	link := json.RawMessage(`[{"ifname":"docker0","ifindex":3,"promiscuity":0,"linkinfo":{"info_kind":"bridge"}}]`)
	address := json.RawMessage(`[{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]}]`)
	route := json.RawMessage(`[{"dst":"172.17.0.0/16","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":["linkdown"]}]`)
	table := map[string]any{"table": map[string]any{"family": "ip", "name": "nat", "handle": json.Number("1")}}
	base := func(name, hook string, priority int) map[string]any {
		return map[string]any{"chain": map[string]any{"family": "ip", "table": "nat", "name": name, "type": "nat", "hook": hook, "prio": json.Number(stringMustInt(priority)), "policy": "accept", "handle": json.Number("2")}}
	}
	custom := map[string]any{"chain": map[string]any{"family": "ip", "table": "nat", "name": "DOCKER", "handle": json.Number("6")}}
	counter := func() any {
		return map[string]any{"counter": map[string]any{"packets": json.Number("0"), "bytes": json.Number("0")}}
	}
	match := func(key string, right any, op string) any {
		left := map[string]any{"meta": map[string]any{"key": key}}
		if key == "saddr" || key == "daddr" {
			left = map[string]any{"payload": map[string]any{"protocol": "ip", "field": key}}
		}
		return map[string]any{"match": map[string]any{"left": left, "right": right, "op": op}}
	}
	prefix := func(addr string, bits int) any {
		return map[string]any{"prefix": map[string]any{"addr": addr, "len": json.Number(stringMustInt(bits))}}
	}
	xt := func(name, kind string) any { return map[string]any{"xt": map[string]any{"name": name, "type": kind}} }
	rule := func(chain string, expr ...any) map[string]any {
		return map[string]any{"rule": map[string]any{"family": "ip", "table": "nat", "chain": chain, "handle": json.Number("7"), "expr": expr}}
	}
	objects := []map[string]any{
		table, base("PREROUTING", "prerouting", -100), base("INPUT", "input", 100), base("OUTPUT", "output", -100), base("POSTROUTING", "postrouting", 100), custom,
		rule("PREROUTING", xt("addrtype", "match"), counter(), map[string]any{"jump": map[string]any{"target": "DOCKER"}}),
		rule("OUTPUT", match("daddr", prefix("127.0.0.0", 8), "!="), xt("addrtype", "match"), counter(), map[string]any{"jump": map[string]any{"target": "DOCKER"}}),
		rule("POSTROUTING", match("oifname", "docker0", "!="), match("saddr", prefix("172.17.0.0", 16), "=="), counter(), xt("MASQUERADE", "target")),
		rule("DOCKER", match("iifname", "docker0", "=="), counter(), map[string]any{"return": nil}),
	}
	nftText := []byte(strings.Join([]string{
		"-P PREROUTING ACCEPT", "-P INPUT ACCEPT", "-P OUTPUT ACCEPT", "-P POSTROUTING ACCEPT", "-N DOCKER",
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
		"-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER",
		"-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE",
		"-A DOCKER -i docker0 -j RETURN",
	}, "\n") + "\n")
	legacy := []byte("-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n")
	return link, address, route, objects, nftText, legacy
}

func stringMustInt(x int) string {
	if x < 0 {
		return "-" + stringMustInt(-x)
	}
	if x == 0 {
		return "0"
	}
	s := ""
	for x > 0 {
		s = string('0'+rune(x%10)) + s
		x /= 10
	}
	return s
}

func dockerNATObjectsFromJSON(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var out []map[string]any
	if e := d.Decode(&out); e != nil {
		t.Fatal(e)
	}
	return out
}

func dockerNATClone(t *testing.T, items []map[string]any) []map[string]any {
	t.Helper()
	b, e := json.Marshal(items)
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var result []map[string]any
	if e := d.Decode(&result); e != nil {
		t.Fatal(e)
	}
	return result
}

func TestDockerNATExactBackendBridgeAndRootNetfilterGraph(t *testing.T) {
	link, address, route, objects, text, legacy := dockerNATFixture()
	if !strictDockerNATSnapshot(link, address, route, objects, text, legacy, "docker0", "ens3") {
		t.Fatal("canonical bounded Docker IPv4 nat shape rejected")
	}
	if b := dockerNATBridgeFromPolicy(text); b != "docker0" {
		t.Fatalf("could not independently read actual bridge: %s", b)
	}
	for _, bad := range [][]byte{nil, []byte("garbage"), []byte(strings.Replace(string(text), "-i docker0", "-i lo", 1)), append(append([]byte{}, text...), []byte("-A DOCKER -j SNAT\n")...)} {
		if b := dockerNATBridgeFromPolicy(bad); b != "" {
			t.Fatalf("unsafe Docker bridge discovered: %s", b)
		}
	}
	// Independent Debian13 kernel renders an unmaterialized empty INPUT
	// chain, reverse ordering of two pure POSTROUTING matches and no
	// linkdown flag on an unconnected but UP synthetic bridge. These are
	// exact equivalent shapes, NOT broad acceptance of foreign rules.
	debian13 := dockerNATClone(t, objects)
	debian13 = append(debian13[:2], debian13[3:]...)
	post := debian13[7]["rule"].(map[string]any)["expr"].([]any)
	post[0], post[1] = post[1], post[0]
	noLinkDown := json.RawMessage(`[{"dst":"172.17.0.0/16","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":[]}]`)
	if !strictDockerNATSnapshot(link, address, noLinkDown, debian13, text, legacy, "docker0", "ens3") {
		t.Fatal("kernel-equivalent Debian13 NAT renderer rejected")
	}
	// Counters and handles change during ordinary traffic. They are not
	// effect grammar and must not cause false drift in a read-only report.
	// The bridge identity is derived from the observed NAT grammar, not a
	// hard-coded device name. Custom Docker bridges remain possible only if
	// both independent backends and the kernel bridge agree exactly.
	newBridge := "br-qa123"
	if !strictDockerNATSnapshot(
		json.RawMessage(strings.ReplaceAll(string(link), "docker0", newBridge)),
		json.RawMessage(strings.ReplaceAll(string(address), "docker0", newBridge)),
		json.RawMessage(strings.ReplaceAll(string(route), "docker0", newBridge)),
		func() []map[string]any {
			data, _ := json.Marshal(objects)
			return dockerNATObjectsFromJSON(t, []byte(strings.ReplaceAll(string(data), "docker0", newBridge)))
		}(),
		[]byte(strings.ReplaceAll(string(text), "docker0", newBridge)), legacy, newBridge, "ens3",
	) {
		t.Fatal("nondefault but proven bridge was rejected")
	}
	if bridge := dockerNATBridgeFromPolicy([]byte(strings.ReplaceAll(string(text), "docker0", newBridge))); bridge != newBridge {
		t.Fatal("unexpected hardcoded bridge")
	}
	items := dockerNATClone(t, objects)
	rule := items[6]["rule"].(map[string]any)
	rule["handle"] = json.Number("777")
	expr := rule["expr"].([]any)
	expr[1].(map[string]any)["counter"].(map[string]any)["packets"] = json.Number("130421")
	if !strictDockerNATSnapshot(link, address, route, items, text, legacy, "docker0", "ens3") {
		t.Fatal("volatile counter or handle rejected")
	}
	// A separate existing NOTRACK/CT owner is not silently reclassified
	// as Docker. It belongs to the other host-ingress gate and remains a
	// separate foreign owner.
	items = append(items, hostNFTFixture("output", map[string]any{"xt": map[string]any{"name": "CT", "type": "target"}})...)
	if !strictDockerNATSnapshot(link, address, route, items, text, legacy, "docker0", "ens3") {
		t.Fatal("independent NOTRACK owner incorrectly treated as NAT")
	}
	risk, e := generalHostForeignNFTEffects(items)
	if e != nil || !risk.ForeignNAT || !risk.OpaqueOutputCT {
		t.Fatalf("independent owners lost: %+v %v", risk, e)
	}
}

func TestDockerNATRefusesForeignOwnershipAndAmbiguousBridge(t *testing.T) {
	link, address, route, objects, text, legacy := dockerNATFixture()
	test := func(label string, makeCase func(*json.RawMessage, *json.RawMessage, *json.RawMessage, *[]map[string]any, *[]byte, *[]byte, *string, *string)) {
		t.Run(label, func(t *testing.T) {
			a, b, c := append(json.RawMessage(nil), link...), append(json.RawMessage(nil), address...), append(json.RawMessage(nil), route...)
			d := dockerNATClone(t, objects)
			e, f := append([]byte(nil), text...), append([]byte(nil), legacy...)
			bridge, underlay := "docker0", "ens3"
			makeCase(&a, &b, &c, &d, &e, &f, &bridge, &underlay)
			if strictDockerNATSnapshot(a, b, c, d, e, f, bridge, underlay) {
				t.Fatal("ambiguous or foreign Docker NAT signature admitted")
			}
		})
	}
	test("foreign underlay is docker", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*underlay = "docker0"
	})
	test("wrong bridge name", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*bridge = "br-unknown"
	})
	test("renamed bridge", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*a = json.RawMessage(`[{"ifname":"docker0","ifindex":3,"promiscuity":0,"linkinfo":{"info_kind":"veth"}}]`)
	})
	test("bridge promisc", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*a = json.RawMessage(`[{"ifname":"docker0","ifindex":3,"promiscuity":1,"linkinfo":{"info_kind":"bridge"}}]`)
	})
	test("extra address", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*b = json.RawMessage(`[{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"},{"family":"inet","local":"10.0.0.1","prefixlen":24,"scope":"global"}]}]`)
	})
	test("bridge overly broad mixed public subnet", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*b = json.RawMessage(`[{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":8,"scope":"global"}]}]`)
	})
	test("bridge public source", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*b = json.RawMessage(`[{"ifname":"docker0","addr_info":[{"family":"inet","local":"8.8.8.8","prefixlen":16,"scope":"global"}]}]`)
	})
	test("foreign route", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*c = json.RawMessage(`[{"dst":"0.0.0.0/0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1"}]`)
	})
	test("extra route", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*c = json.RawMessage(`[{"dst":"172.17.0.0/16","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1"},{"dst":"10.0.0.0/8","protocol":"static","scope":"link"}]`)
	})
	test("legacy NAT owner", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*f = append(*f, []byte("-A OUTPUT -j DNAT\n")...)
	})
	test("wrong translated source", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		row := (*d)[8]["rule"].(map[string]any)
		row["expr"].([]any)[1].(map[string]any)["match"].(map[string]any)["right"].(map[string]any)["prefix"].(map[string]any)["len"] = json.Number("15")
	})
	test("foreign published DNAT", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append(*d, map[string]any{"rule": map[string]any{"family": "ip", "table": "nat", "chain": "DOCKER", "expr": []any{map[string]any{"dnat": map[string]any{"addr": "172.17.0.2"}}}}})
	})
	test("foreign postroute mutation", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append(*d, map[string]any{"rule": map[string]any{"family": "inet", "table": "foreign", "chain": "postrouting", "expr": []any{map[string]any{"masquerade": nil}}}})
	})
	test("missing independent opaque corroboration", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*e = []byte(strings.Replace(string(*e), "--dst-type LOCAL", "--dst-type MULTICAST", 1))
	})
	test("unexpected iptables nft rule", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*e = append(*e, []byte("-A OUTPUT -j REDIRECT\n")...)
	})
	test("nonaccept output policy", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		(*d)[3]["chain"].(map[string]any)["policy"] = "drop"
	})
	test("injected route statement", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		(*d)[6]["rule"].(map[string]any)["expr"].([]any)[0].(map[string]any)["xt"].(map[string]any)["name"] = "MARK"
	})
	test("missing required prerouting base chain", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append((*d)[:1], (*d)[2:]...)
	})
	test("extra empty chain", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append(*d, map[string]any{"chain": map[string]any{"family": "ip", "table": "nat", "name": "unexpected"}})
	})
	test("nat swapped with effectful expression", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		row := (*d)[8]["rule"].(map[string]any)
		exprs := row["expr"].([]any)
		exprs[0], exprs[2] = exprs[2], exprs[0]
	})
	test("duplicate Docker nft chain", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append(*d, (*d)[5])
	})
	test("unknown extra Docker nft rule", func(a, b, c *json.RawMessage, d *[]map[string]any, e, f *[]byte, bridge, underlay *string) {
		*d = append(*d, (*d)[9])
	})
}

func TestGeneralHostBoundaryDockerNATShapeStillNeverAuthorizesApply(t *testing.T) {
	o := hostBoundaryFixture()
	_, _, _, objects, _, _ := dockerNATFixture()
	o.nft = objects
	o.dockerNATShape = dockerNATObservedShape
	r := assessSmartTUNHostBoundary(o, "ens3")
	if r.DockerNATShape != dockerNATObservedShape || r.ActivationReady || r.GeneralHostAdmitted || !hasBoundaryReason(r, "foreign_nat_ownership_unverified") || !hasBoundaryReason(r, "general_host_admission_not_implemented") {
		t.Fatal(r)
	}
	o.dockerNATShape = dockerNATUnverified
	r = assessSmartTUNHostBoundary(o, "ens3")
	if r.DockerNATShape != dockerNATUnverified || r.ActivationReady {
		t.Fatal(r)
	}
	// A syntactically known Docker NAT owner does not mean other external
	// xtables, future rules or surviving protected inbound replies are safe.
	if netip.MustParsePrefix("172.17.0.0/16").Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("fixture subnet is not bounded")
	}
}
