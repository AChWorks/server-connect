package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

// No selected profile, CLI state, external target or kernel mutation may be
// touched for malformed host boundaries. Valid requests are read-only and
// deliberately guarded behind privileged native inspection.
func TestSmartTUNHostBoundaryCLIRejectsUnsafeParametersWithoutState(t *testing.T) {
	for _, args := range [][]string{
		{"smart-tun-host-boundary"},
		{"smart-tun-host-boundary", "--underlay-if", "ens3"},
		{"smart-tun-host-boundary", "--management-peer", "8.8.8.8", "--underlay-if", ""},
		{"smart-tun-host-boundary", "--management-peer", "::ffff:8.8.8.8", "--underlay-if", "ens3"},
		{"smart-tun-host-boundary", "--management-peer", "203.0.113.6", "--underlay-if", "ens3"},
		{"smart-tun-host-boundary", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "extra"},
		{"smart-tun-host-boundary", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--trust-host"},
	} {
		t.Run(args[len(args)-1], func(t *testing.T) {
			m := sc.New(filepath.Join(t.TempDir(), "uncreated"), "", sc.DefaultPort)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdout
			os.Stdout = writer
			rc := run(true, m, args)
			_ = writer.Close()
			os.Stdout = old
			var reply envelope
			e := json.NewDecoder(reader).Decode(&reply)
			_ = reader.Close()
			if e != nil || rc != 1 || reply.OK || reply.Error == nil || reply.Error.Code != "invalid_arguments" {
				t.Fatalf("unsafe CLI arguments not rejected: %#v reply=%+v err=%v", args, reply, e)
			}
			if _, err := os.Stat(m.Dir); !os.IsNotExist(err) {
				t.Fatalf("invalid read-only CLI request wrote state: %v", err)
			}
		})
	}
}
