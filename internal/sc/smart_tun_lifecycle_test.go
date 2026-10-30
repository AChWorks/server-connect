package sc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func savedSmartTUNFixture() SmartTUNCandidateOptions {
	return SmartTUNCandidateOptions{
		TunnelInterface: "sctunqa0", UnderlayInterface: "scqaedge0",
		TunnelIPv4: "172.31.99.1/30", ProtectedCIDRs: []string{"10.254.72.0/30"},
		DomesticCIDRs: []string{"5.22.0.10/32"},
	}
}

func TestSmartTUNDurableStopAndCleanupPhases(t *testing.T) {
	for _, pair := range []struct {
		phase    string
		revision uint64
	}{
		{"trial_pending", 1}, {"trial_stop_requested", 2},
		{"trial_recovered", 2}, {"trial_recovered", 3}, {"trial_cleanup_pending", 4},
	} {
		record := trialV4Example()
		record.CoreStartAttempted = true
		record.Phase, record.Revision = pair.phase, pair.revision
		raw, _ := json.Marshal(record)
		if _, err := decodeSmartTUNTrial(raw); err != nil {
			t.Fatalf("valid phase %s/%d rejected: %v", pair.phase, pair.revision, err)
		}
		if pair.phase != "trial_pending" && smartTUNTrialMayRemainPending(record, "active", true, true, 1) {
			t.Fatalf("%s left the core pending before the old deadline", pair.phase)
		}
		if !matchingSmartTUNOperation(record, record.OperationID, record.Revision) ||
			matchingSmartTUNOperation(record, strings.Repeat("b", 32), record.Revision) ||
			matchingSmartTUNOperation(record, record.OperationID, record.Revision+1) {
			t.Fatal("operation/revision comparison accepted a stale or unrelated request")
		}
		for wrong := uint64(0); wrong < 7; wrong++ {
			if smartTUNTrialPhaseRevisionValid(pair.phase, wrong) {
				continue
			}
			record.Revision = wrong
			raw, _ := json.Marshal(record)
			if _, err := decodeSmartTUNTrial(raw); err == nil {
				t.Fatalf("accepted impossible phase/revision %s/%d", pair.phase, wrong)
			}
		}
	}
}

func TestSmartTUNTransitionReloadRejectsValidJournalSubstitution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*smartTUNTrialJournal)
	}{
		{"other-operation", func(r *smartTUNTrialJournal) { r.OperationID = strings.Repeat("b", 32) }},
		{"same-operation-baseline", func(r *smartTUNTrialJournal) { r.BaselineSHA256 = strings.Repeat("3", 64) }},
		{"same-operation-profile", func(r *smartTUNTrialJournal) { r.ProfileID = "1111111111111111" }},
		{"same-operation-start-intent", func(r *smartTUNTrialJournal) { r.CoreStartAttempted = false }},
		{"same-operation-phase", func(r *smartTUNTrialJournal) { r.Phase, r.Revision = "trial_recovered", 3 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			m := New(dir, DefaultCore, DefaultPort)
			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				expected := trialV4Example()
				expected.CoreStartAttempted = true
				expected.Phase, expected.Revision = "trial_recovered", 3
				credential := []byte("exact-operation-credential")
				expected.ConfigSHA256 = sha256Hex(credential)
				if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, credential, nil); err != nil {
					return err
				}
				if err := writeSmartTUNTrialLocked(store, expected, nil); err != nil {
					return err
				}
				initialID, err := reloadSmartTUNTrialLocked(store, expected)
				if err != nil {
					return err
				}
				// A legitimate durable transition publishes a new inode. The
				// check must accept the exact new record, not pin the old inode.
				expected.Phase, expected.Revision = "trial_cleanup_pending", 4
				if err := writeSmartTUNTrialLocked(store, expected, &initialID); err != nil {
					return err
				}
				transitionID, err := reloadSmartTUNTrialLocked(store, expected)
				if err != nil || transitionID == initialID {
					t.Fatalf("exact atomic transition did not receive its new identity: %v", err)
				}
				foreign := expected
				tc.change(&foreign)
				if err := validateSmartTUNTrial(foreign); err != nil {
					t.Fatalf("substitution fixture must remain valid: %v", err)
				}
				foreignBytes, _ := json.Marshal(foreign)
				foreignPath := filepath.Join(dir, "foreign-journal")
				if err := os.WriteFile(foreignPath, foreignBytes, 0600); err != nil {
					return err
				}
				if err := os.Rename(foreignPath, filepath.Join(dir, activationJournalFilename)); err != nil {
					return err
				}
				foreignData, foreignID, err := store.readJournal()
				if err != nil {
					return err
				}
				adopted, err := reloadSmartTUNTrialLocked(store, expected)
				if ErrorCode(err) != "activation_journal_conflict" || adopted != (activationJournalFileIdentity{}) {
					t.Fatalf("valid substituted journal identity was adopted: %+v %v", adopted, err)
				}
				after, afterID, err := store.readJournal()
				if err != nil || afterID != foreignID || !bytes.Equal(after, foreignData) {
					t.Fatalf("substituted journal evidence was changed: %v", err)
				}
				secret, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
				if err != nil || !bytes.Equal(secret, credential) {
					t.Fatalf("failed reload discarded credential evidence: %v", err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSavedSmartTUNPolicyStrictScopeAndNoSecrets(t *testing.T) {
	policy := smartTUNSavedPolicy{Version: 1, ManagementPeerIP: "10.254.72.2", Options: savedSmartTUNFixture()}
	raw, _ := json.Marshal(policy)
	if _, err := decodeSavedSmartTUNPolicy(raw); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "uuid", "outbound", "profile_id", "operation_id", "core_start_attempted"} {
		if bytes.Contains(raw, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("saved policy contains transient/credential field %s", forbidden)
		}
	}
	for _, bad := range []string{
		string(raw) + " {}",
		strings.Replace(string(raw), `"version":1`, `"version":2`, 1),
		strings.Replace(string(raw), `"version":1`, `"Version":1`, 1),
		strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(string(raw), `"management_peer_ip":"10.254.72.2"`, `"management_peer_ip":"8.8.8.8"`, 1),
		strings.Replace(string(raw), `"tunnel_interface":`, `"Tunnel_Interface":`, 1),
		strings.Replace(string(raw), `"tunnel_ipv6":"",`, "", 1),
		strings.Replace(string(raw), `"tunnel_ipv6":""`, `"tunnel_ipv6":null`, 1),
		strings.Replace(string(raw), `"domestic_cidrs":["5.22.0.10/32"]`, `"domestic_cidrs":["0.0.0.0/0"]`, 1),
		strings.Replace(string(raw), `"domain_exceptions":null`, `"domain_exceptions":[{"domain":"example.com","suffix":false,"via":"direct"}]`, 1),
		strings.Replace(string(raw), `"exceptions":null`, `"exceptions":null,"password":"secret"`, 1),
	} {
		if _, err := decodeSavedSmartTUNPolicy([]byte(bad)); ErrorCode(err) != "saved_policy_invalid" {
			t.Fatalf("untrusted saved policy accepted or misclassified: %q %v", bad, err)
		}
	}
}

func TestSavedSmartTUNPolicyBytesAndIdentityRemainBoundAcrossAdmission(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := checkSavedSmartTUNPolicyLocked(store, nil); err != nil {
			return err
		}
		if err := saveSmartTUNPolicyLocked(store, savedSmartTUNFixture(), "10.254.72.2"); err != nil {
			return err
		}
		original, identity, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
		if err != nil {
			return err
		}
		binding := smartTUNSavedPolicyBinding{identity: identity, digest: sha256Hex(original)}
		if err := checkSavedSmartTUNPolicyLocked(store, &binding); err != nil {
			return err
		}
		if err := saveSmartTUNPolicyLocked(store, savedSmartTUNFixture(), "10.254.72.2"); err != nil {
			return err
		}
		unchanged, sameID, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
		if err != nil || sameID != identity || !bytes.Equal(original, unchanged) {
			t.Fatalf("unchanged configuration was rewritten: %v", err)
		}
		// Same inode with semantically identical but changed bytes is stale.
		path := filepath.Join(dir, smartTUNSavedPolicyFile)
		if err := os.WriteFile(path, append(original, '\n'), 0600); err != nil {
			return err
		}
		if err := checkSavedSmartTUNPolicyLocked(store, &binding); ErrorCode(err) != "saved_policy_conflict" {
			t.Fatalf("saved bytes changed under admitted identity: %v", err)
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			return err
		}
		// Equal bytes in a replacement inode must also fail the binding.
		if err := os.Rename(path, filepath.Join(dir, "old-policy")); err != nil {
			return err
		}
		if err := os.WriteFile(path, original, 0600); err != nil {
			return err
		}
		if err := checkSavedSmartTUNPolicyLocked(store, &binding); ErrorCode(err) != "saved_policy_conflict" {
			t.Fatalf("replaced policy identity accepted: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	status, err := m.InspectSavedSmartTUNTrialPolicy()
	if err != nil || !status.Present || !status.ExperimentOnly || status.Options == nil ||
		status.ManagementPeerIP != "10.254.72.2" || !journalHex64.MatchString(status.SHA256) {
		t.Fatalf("invalid nonsecret saved-policy status: %+v %v", status, err)
	}
}

func TestSmartTUNCredentialRemovalRefusesReplacementAndRetainsEvidence(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		data := []byte("original-secret")
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, data, nil); err != nil {
			return err
		}
		_, identity, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
		if err != nil {
			return err
		}
		path := filepath.Join(dir, smartTUNTrialConfigFile)
		if err := os.Rename(path, filepath.Join(dir, "original-credential")); err != nil {
			return err
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return err
		}
		if err := store.removeSmartTUNCredential(identity, sha256Hex(data)); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("removed foreign same-byte credential: %v", err)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("replacement was removed: %v", err)
		}
		_, replacement, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
		if err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte("changed-secret"), 0600); err != nil {
			return err
		}
		if err := store.removeSmartTUNCredential(replacement, sha256Hex(data)); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("removed mutated credential bytes: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Bound special-file rejection in a subprocess. A missing O_NONBLOCK must
// fail this test, not leave the full suite waiting forever on a FIFO open.
func TestSmartTUNStateRejectsSpecialFilesWithoutBlocking(t *testing.T) {
	if dir := os.Getenv("SC_TUN_STATE_FIFO_CHILD"); dir != "" {
		m := New(dir, DefaultCore, DefaultPort)
		if err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
			for _, name := range []string{smartTUNSavedPolicyFile, smartTUNTrialConfigFile} {
				path := filepath.Join(dir, name)
				if err := syscall.Mkfifo(path, 0600); err != nil {
					return err
				}
				if _, _, err := store.readSmartTUNFile(name); ErrorCode(err) != "trial_resource_conflict" {
					t.Fatalf("FIFO read accepted: %v", err)
				}
				if err := store.writeSmartTUNFile(name, []byte("must-not-write"), nil); ErrorCode(err) != "trial_resource_conflict" {
					t.Fatalf("FIFO replaced: %v", err)
				}
				if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("FIFO evidence lost: %v", err)
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := privateJournalTempDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSmartTUNStateRejectsSpecialFilesWithoutBlocking$")
	cmd.Env = append(os.Environ(), "SC_TUN_STATE_FIFO_CHILD="+dir)
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("special-file operations failed or blocked: %v %v %s", err, ctx.Err(), output)
	}
}

func TestSmartTUNStateRejectsLinksAndBoundsBeforeReading(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "oversize", "public-mode"} {
		t.Run(kind, func(t *testing.T) {
			dir := privateJournalTempDir(t)
			path := filepath.Join(dir, smartTUNSavedPolicyFile)
			original := filepath.Join(dir, "original")
			if err := os.WriteFile(original, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(original, path)
			case "hardlink":
				err = os.Link(original, path)
			case "oversize":
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), activationJournalMaxBytes+1), 0600)
			case "public-mode":
				err = os.WriteFile(path, []byte("public"), 0600)
				if err == nil {
					err = os.Chmod(path, 0644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			m := New(dir, DefaultCore, DefaultPort)
			err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				_, _, err := store.readSmartTUNFile(smartTUNSavedPolicyFile)
				return err
			})
			if ErrorCode(err) != "trial_resource_conflict" {
				t.Fatalf("untrusted state accepted: %v", err)
			}
			if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
				t.Fatal("untrusted evidence removed")
			}
		})
	}
}
