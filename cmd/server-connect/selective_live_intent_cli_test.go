package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AChWorks/server-connect/internal/sc"
)

func TestSelectiveLiveCLIRefusesInvalidArgumentsBeforeStateInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	m := sc.New(dir, "", 0)
	for _, args := range [][]string{
		{"selective-verify-intent"},
		{"selective-verify-intent", "--operation-id", "bad", "--revision", "1"},
		{"selective-verify-intent", "--operation-id", strings.Repeat("0", 32), "--revision", "0"},
		{"selective-verify-intent", "--operation-id", strings.Repeat("0", 32), "--revision", "2"},
		{"selective-verify-intent", "--operation-id", strings.Repeat("0", 32), "--revision", "1", "extra"},
		{"selective-verify-intent", "--unsupported", "x"},
	} {
		code, stdout, stderr := hostDriftCapturedOutput(t, func() int { return run(true, m, args) })
		if code == 0 || stderr != "" || !strings.Contains(stdout, "invalid_arguments") ||
			strings.Contains(stdout, `"data"`) {
			t.Fatalf("invalid arguments created a live receipt: %d %s %s", code, stdout, stderr)
		}
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("invalid command created private state: %v", err)
		}
	}
}

func TestSelectiveLiveCLIWrongOperationAndGenericRecordPreserveJournal(t *testing.T) {
	m, path, _ := preparedSelectiveCLIFixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := hostDriftCapturedOutput(t, func() int {
		return run(true, m, []string{"selective-verify-intent",
			"--operation-id", strings.Repeat("0", 32), "--revision", "1"})
	})
	if code == 0 || stderr != "" || !strings.Contains(stdout, "activation_journal_conflict") ||
		strings.Contains(stdout, `"data"`) {
		t.Fatalf("wrong operation was accepted: %d %s %s", code, stdout, stderr)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected verification damaged persisted selective record")
	}
	generic, genericPath, _ := privateStatusFixture(t)
	original, err := os.ReadFile(genericPath)
	if err != nil {
		t.Fatal(err)
	}
	status := bytes.Replace(original, []byte(`"phase":"uncertain"`), []byte(`"phase":"prepared"`), 1)
	status = bytes.Replace(status, []byte(`"revision":2`), []byte(`"revision":1`), 1)
	if err := os.WriteFile(genericPath, status, 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = hostDriftCapturedOutput(t, func() int {
		return run(true, generic, []string{"selective-verify-intent",
			"--operation-id", "0123456789abcdef0123456789abcdef", "--revision", "1"})
	})
	if code == 0 || stderr != "" || !strings.Contains(stdout, "activation_journal_conflict") ||
		strings.Contains(stdout, `"data"`) {
		t.Fatalf("generic journal was silently retyped: %d %s %s", code, stdout, stderr)
	}
	remaining, err := os.ReadFile(genericPath)
	if err != nil || !bytes.Equal(status, remaining) {
		t.Fatal("generic journal changed during invalid verify")
	}
}
