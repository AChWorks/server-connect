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
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--ack-disposable-host", "--qa-kill-at", "after-start"},
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--native-link-if", "sctunqa0"},
		{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "ens3", "--native-link-if", "sctunqa0", "--ack-disposable-host=false"},
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

func TestHostNativeQACLIUninstalledOrUnsupportedFaultHasNoState(t *testing.T) {
	for _, flags := range [][]string{
		{"--native-link-if", "sctunv70"},
		{"--native-link-if", "sctunv70", "--qa-kill-at", "after-start"},
		{"--native-link-if", "invalid/if"},
	} {
		args := append([]string{"host-capture-preparation-qa", "--management-peer", "8.8.8.8", "--underlay-if", "eth0", "--ack-disposable-host"}, flags...)
		path := filepath.Join(t.TempDir(), "never-created")
		m := sc.New(path, sc.DefaultCore, sc.DefaultPort)
		read, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := os.Stdout
		os.Stdout = write
		code := run(true, m, args)
		_ = write.Close()
		os.Stdout = saved
		var response struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		err = json.NewDecoder(read).Decode(&response)
		_ = read.Close()
		if err != nil || code != 1 || response.OK || (response.Error.Code != "trial_unsupported" && response.Error.Code != "invalid_arguments") {
			t.Fatalf("uninstalled/invalid native QA accepted: args=%v response=%+v err=%v", args, response, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("native QA created state without installed authority: %v", err)
		}
	}
}
