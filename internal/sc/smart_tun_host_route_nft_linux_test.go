//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"testing"
)

func hostRouteSyntheticRawNFT(t *testing.T) []map[string]any {
	t.Helper()
	raw := `{"nftables":[`
	first := true
	push := func(s string) {
		if !first {
			raw += ","
		}
		first = false
		raw += s
	}
	for _, f := range []string{"ip", "ip6"} {
		push(`{"table":{"family":"` + f + `","name":"raw","handle":1}}`)
		for _, name := range []string{"PREROUTING", "OUTPUT"} {
			hook := "prerouting"
			field := "dport"
			if name == "OUTPUT" {
				hook = "output"
				field = "sport"
			}
			push(`{"chain":{"family":"` + f + `","table":"raw","name":"` + name + `","handle":2,"type":"filter","hook":"` + hook + `","prio":-300,"policy":"accept"}}`)
			push(`{"rule":{"family":"` + f + `","table":"raw","chain":"` + name + `","handle":3,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"` + field + `"}},"right":28997}},{"counter":{"packets":0,"bytes":0}},{"xt":{"type":"target","name":"CT"}}]}}`)
		}
	}
	raw += `]}`
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.UseNumber()
	var doc struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.NFTables
}

func TestHostRouteV9StrictRawNOTRACKClassifier(t *testing.T) {
	r := hostRouteExample(t)
	ports := map[uint16]bool{28997: true}
	rows := hostRouteSyntheticRawNFT(t)
	if kept, err := hostRouteNFTFilter(rows, r.nativeView(), r.Progress.Ingress, ports, false); err != nil || len(kept) != 0 {
		t.Fatalf("known paired cross-family NOTRACK rejected: %v kept=%d", err, len(kept))
	}
	cases := []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
	}{
		{"missing_v6_output", func(in []map[string]any) []map[string]any { return in[:len(in)-1] }},
		{"duplicate_rule", func(in []map[string]any) []map[string]any { return append(in, in[len(in)-1]) }},
		{"raw_native_extension", func(in []map[string]any) []map[string]any {
			return append(in, map[string]any{"flowtable": map[string]any{"family": "ip", "table": "raw", "name": "unknown"}})
		}},
		{"unverified_port", func(in []map[string]any) []map[string]any {
			in[2]["rule"].(map[string]any)["expr"].([]any)[0].(map[string]any)["match"].(map[string]any)["right"] = json.Number("28998")
			return in
		}},
		{"opaque_target", func(in []map[string]any) []map[string]any {
			in[2]["rule"].(map[string]any)["expr"].([]any)[2].(map[string]any)["xt"].(map[string]any)["name"] = "NOTRACK"
			return in
		}},
		{"different_raw_hook", func(in []map[string]any) []map[string]any {
			in[1]["chain"].(map[string]any)["hook"] = "postrouting"
			return in
		}},
		{"different_priority", func(in []map[string]any) []map[string]any {
			in[1]["chain"].(map[string]any)["prio"] = json.Number("-299")
			return in
		}},
		{"foreign_nat_without_docker", func(in []map[string]any) []map[string]any {
			return append(in, map[string]any{"table": map[string]any{"family": "ip", "name": "nat", "handle": 44}})
		}},
		{"unexpected_table_action", func(in []map[string]any) []map[string]any {
			return append(in, map[string]any{"rule": map[string]any{"family": "inet", "table": "guest", "expr": []any{map[string]any{"mangle": map[string]any{"key": "meta mark"}}}}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := hostRouteSyntheticRawNFT(t)
			forged := tc.mutate(original)
			if _, err := hostRouteNFTFilter(forged, r.nativeView(), r.Progress.Ingress, ports, false); err == nil {
				t.Fatal("unsupported foreign raw/NAT owner was adopted as safe")
			}
		})
	}
}
