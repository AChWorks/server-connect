//go:build linux

package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
)

// The official Core can add two accept rules to Docker's pre-existing
// DOCKER-USER chain when auto_redirect owns a TUN. After SIGKILL they can
// outlive the Core. Never delete the chain or an unrelated Docker rule:
// recognize only the Core's exact, TUN-bound rule expressions and handles.
func nativeDockerRecoveryActions(raw string, tunnelIF string) ([]nativeAction, error) {
	conflict := func() error { return errors.New("native recovery: ambiguous Docker compatibility rule") }
	if len(raw) == 0 || len(raw) > firewallSnapshotMaxBytes {
		return nil, conflict()
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	var top map[string]json.RawMessage
	if d.Decode(&top) != nil || len(top) != 1 {
		return nil, conflict()
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return nil, conflict()
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(top["nftables"], &entries) != nil || len(entries) < 2 || len(entries) > firewallMaxObjects {
		return nil, conflict()
	}
	var meta map[string]any
	md := json.NewDecoder(bytes.NewReader(entries[0]["metainfo"]))
	md.UseNumber()
	if md.Decode(&meta) != nil || len(entries[0]) != 1 || !validNftMetainfo(meta) {
		return nil, conflict()
	}
	var actions []nativeAction
	seenComments := make(map[string]bool)
	seenHandles := make(map[uint64]bool)
	for _, entry := range entries[1:] {
		if len(entry) != 1 {
			return nil, conflict()
		}
		data, hasRule := entry["rule"]
		if !hasRule {
			continue
		}
		var rule map[string]json.RawMessage
		if json.Unmarshal(data, &rule) != nil {
			return nil, conflict()
		}
		var comment, chain, family, table string
		_ = json.Unmarshal(rule["comment"], &comment)
		_ = json.Unmarshal(rule["chain"], &chain)
		_ = json.Unmarshal(rule["family"], &family)
		_ = json.Unmarshal(rule["table"], &table)
		// Do not adopt someone else's sing-box installation. If a rule
		// presents one of our reserved comments outside the expected chain,
		// or Core's Docker family changes, stop before modifying anything.
		key := ""
		switch comment {
		case "!sing-box: Docker compatibility input from tun":
			key = "iifname"
		case "!sing-box: Docker compatibility output to tun":
			key = "oifname"
		default:
			if chain == "DOCKER-USER" && strings.HasPrefix(comment, "!sing-box: Docker compatibility") {
				return nil, conflict()
			}
			continue
		}
		if family != "ip" || table != "filter" || chain != "DOCKER-USER" ||
			len(rule) != 6 || seenComments[comment] {
			return nil, conflict()
		}
		var expressions []map[string]json.RawMessage
		if json.Unmarshal(rule["expr"], &expressions) != nil || len(expressions) != 3 ||
			len(expressions[0]) != 1 || len(expressions[1]) != 1 || len(expressions[2]) != 1 {
			return nil, conflict()
		}
		var match any
		if json.Unmarshal(expressions[0]["match"], &match) != nil {
			return nil, conflict()
		}
		want := map[string]any{"left": map[string]any{"meta": map[string]any{"key": key}},
			"op": "==", "right": tunnelIF}
		if !reflect.DeepEqual(match, want) || !bytes.Equal(bytes.TrimSpace(expressions[2]["accept"]), []byte("null")) {
			return nil, conflict()
		}
		var counter map[string]json.Number
		if json.Unmarshal(expressions[1]["counter"], &counter) != nil || len(counter) != 2 {
			return nil, conflict()
		}
		for _, field := range []string{"packets", "bytes"} {
			v, ok := counter[field]
			if !ok {
				return nil, conflict()
			}
			if _, err := strconv.ParseUint(v.String(), 10, 64); err != nil {
				return nil, conflict()
			}
		}
		var handle json.Number
		if json.Unmarshal(rule["handle"], &handle) != nil {
			return nil, conflict()
		}
		number, err := strconv.ParseUint(handle.String(), 10, 64)
		if err != nil || number == 0 || seenHandles[number] {
			return nil, conflict()
		}
		seenComments[comment], seenHandles[number] = true, true
		actions = append(actions, nativeAction{"nft", []string{
			"delete", "rule", "ip", "filter", "DOCKER-USER", "handle", fmt.Sprint(number),
		}})
	}
	return actions, nil
}

func inspectNativeDockerRecovery(ctx context.Context, r nativeKernelRunner, tunnelIF string) ([]nativeAction, error) {
	raw, err := r.output(ctx, "nft", "-j", "-a", "list", "table", "ip", "filter")
	if err != nil {
		return nil, err
	}
	return nativeDockerRecoveryActions(raw, tunnelIF)
}
