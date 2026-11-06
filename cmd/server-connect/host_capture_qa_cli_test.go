package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestHostCaptureQACLIMissingDisposableAcknowledgementDoesNotWriteState(t *testing.T) {
	for _, args := range [][]string{
		{"host-capture-preparation-qa"},
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3"},
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--ack-disposable-host=false"},
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--ack-disposable-host", "unexpected"},
	} {
		dir := filepath.Join(t.TempDir(), "uncreated")
		m := sc.New(dir, "", sc.DefaultPort)
		rd, wr, e := os.Pipe()
		if e != nil {
			t.Fatal(e)
		}
		old := os.Stdout
		os.Stdout = wr
		code := run(true, m, args)
		_ = wr.Close()
		os.Stdout = old
		var envelope struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		e = json.NewDecoder(rd).Decode(&envelope)
		_ = rd.Close()
		if e != nil || code != 1 || envelope.OK || envelope.Error.Code != "invalid_arguments" {
			t.Fatalf("missing QA ack was accepted: args=%v result=%+v err=%v", args, envelope, e)
		}
		if _, e := os.Stat(dir); !os.IsNotExist(e) {
			t.Fatalf("invalid QA CLI wrote state: %v", e)
		}
	}
}
