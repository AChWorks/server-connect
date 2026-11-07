//go:build linux

package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// The existing filesystem seam fails the directory sync only after the real
// private-file write, file sync and rename. This covers retained parent intent,
// not the installed Begin caller's non-injectable published flag or systemd
// timer state; those require an installed executor witness.
func TestHostParentsPostRenameSyncErrorRetainsExactRecoveryIntent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version int
		record  any
	}{
		{"v7", hostNativeJournalVersion, hostNativeExample()},
		{"v8", hostCoreJournalVersion, hostCoreExample()},
		{"v9", hostRouteJournalVersion, hostRouteExample(t)},
		{"v9_supervised", hostRouteJournalVersion, hostSupervisorExample(t, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
			raw, err := json.Marshal(tc.record)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, '\n')
			var publishedIdentity activationJournalFileIdentity
			check := func(store *activationJournalDir) error {
				selected, err := selectTrialRecoveryLocked(store, "", "")
				if err != nil {
					return err
				}
				var got any
				switch selected.version {
				case hostNativeJournalVersion:
					got = selected.hostNative
				case hostCoreJournalVersion:
					got = selected.hostCore
				case hostRouteJournalVersion:
					got = selected.hostRoute
				}
				if selected.version != tc.version || !reflect.DeepEqual(got, tc.record) {
					return errors.New("fresh recovery selector lost the uncertain exact parent")
				}
				return nil
			}
			err = m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				calls := 0
				err := store.writeJournalWithDirSync(raw, nil, func(fd int) error {
					calls++
					got, id, readErr := store.readJournal()
					if fd != int(store.dir.Fd()) || readErr != nil || !bytes.Equal(got, raw) {
						t.Fatalf("fault was not after actual parent rename: %v", readErr)
					}
					publishedIdentity = id
					if err := check(store); err != nil {
						t.Fatal(err)
					}
					return syscall.EIO
				})
				if ErrorCode(err) != "activation_journal_unavailable" || calls != 1 {
					return fmt.Errorf("post-rename EIO was acknowledged: %v calls=%d", err, calls)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			// These are the real uncommitted cleanup entry points. Existing
			// uncertain journal evidence must remain selectable afterward.
			m.disarmUncommittedSmartTUNGuard()
			m.disarmUncommittedSmartTUNHealth([2]smartTUNHealthUnitIdentity{})
			runner := New(m.Dir, DefaultCore, DefaultPort)
			err = runner.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				got, id, err := store.readJournal()
				if err != nil || id != publishedIdentity || !bytes.Equal(got, raw) {
					return errors.New("uncertain parent disappeared or was rewritten by uncommitted cleanup")
				}
				if err := check(store); err != nil {
					return err
				}
				// A second create must conflict, not erase possibly published intent.
				if ErrorCode(store.writeJournal(raw, nil)) != "activation_journal_conflict" {
					return errors.New("new operation overwrote uncertain parent")
				}
				// An explicit same-parent retry can establish the directory
				// durability barrier and must retain the exact decoded operation.
				if err := store.writeJournal(raw, &id); err != nil {
					return err
				}
				return check(store)
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Both actual recovery dispatchers must visit the exact-owned Core while its
// credential exists even when the journal's boot is old. A lost stop response
// deliberately ends this unit test before fixed real-kernel absence observers;
// kernel/reboot acceptance is separate from this service-ordering regression.
func TestHostOldBootRecoveryStopsOwnedCoreBeforeCredentialRetirement(t *testing.T) {
	currentBoot, err := trialBootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{hostCoreJournalVersion, hostRouteJournalVersion} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			r8 := hostCoreLinkedExample()
			if r8.Progress.Ingress.BootID == currentBoot {
				t.Fatal("fixture must use a different boot")
			}
			secret := []byte("old-boot exact owned Core credential")
			r8.Core.ConfigSHA256 = sha256Hex(secret)
			r8.Core.Stage, r8.Core.StartAttempted = "active_observed", true
			r9 := hostRouteExample(t)
			r9.hostCoreJournal = r8
			r9.Version, r9.Intent = hostRouteJournalVersion, hostRouteJournalIntent
			m := New(privateJournalTempDir(t), DefaultCore, DefaultPort)
			state := smartTUNCoreObservationExample("active")
			inactive := smartTUNCoreObservationExample("inactive")
			inactive.identity = state.identity
			stopCalls := 0
			lostResponse := errors.New("test-only lost stop response after exact owned Core became inactive")
			var credentialID activationJournalFileIdentity

			err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				if version == hostCoreJournalVersion {
					if err := writeHostCoreJournal(store, r8, nil); err != nil {
						return err
					}
				} else if err := writeHostRouteJournal(store, r9, nil); err != nil {
					return err
				}
				if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, secret, nil); err != nil {
					return err
				}
				_, credentialID, err = store.readSmartTUNFile(smartTUNTrialConfigFile)
				if err != nil {
					return err
				}
				service := hostCoreRecoveryServices{
					observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
					stop: func(original smartTUNTrialUnitObservation, started, valid bool) error {
						stopCalls++
						if !started || !valid || original.identity != state.identity {
							return errors.New("old-boot Core lost exact start/credential authority")
						}
						data, id, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
						if err != nil || id != credentialID || !bytes.Equal(data, secret) {
							return errors.New("credential was retired before owned Core stop")
						}
						var parent hostCoreJournal
						if version == hostCoreJournalVersion {
							parent, _, err = loadHostCoreJournal(store)
						} else {
							var route hostRouteJournal
							route, _, err = loadHostRouteJournal(store)
							parent = route.hostCoreJournal
						}
						if err != nil || parent.Core.Stage != "stop_requested" ||
							parent.Native.LinkStage != "observed" || parent.Progress.Barrier.Stage != "closed" ||
							parent.Progress.Ingress.NFTStage != "observed" {
							return errors.New("old-boot network progress retired before Core-first stop")
						}
						state = inactive
						return lostResponse
					},
				}
				var receipt TrialReceipt
				if version == hostCoreJournalVersion {
					receipt, err = recoverHostCoreJournalLocked(store, &r8, service)
				} else {
					receipt, err = recoverHostRouteJournalLocked(store, &r9, service)
				}
				if !errors.Is(err, lostResponse) || receipt.RecoveryVerified || stopCalls != 1 || !state.stopped() {
					return fmt.Errorf("old-boot dispatcher skipped or falsely acknowledged Core stop: %+v %v calls=%d", receipt, err, stopCalls)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			// Reopen the real retained parent before retrying credential cleanup.
			err = New(m.Dir, DefaultCore, DefaultPort).withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
				if version == hostCoreJournalVersion {
					r8, _, err = loadHostCoreJournal(store)
				} else {
					r9, _, err = loadHostRouteJournal(store)
				}
				if err != nil {
					return err
				}
				core := &r8.Core
				advance := func(stage string) error { return hostCoreAdvance(store, &r8, stage) }
				if version == hostRouteJournalVersion {
					core = &r9.Core
					advance = func(stage string) error { return hostRouteCoreStagePersist(store, &r9, stage) }
				}
				if core.Stage != "stop_requested" {
					return errors.New("lost stop response discarded durable stop intent")
				}
				service := hostCoreRecoveryServices{
					observe: func() (smartTUNTrialUnitObservation, error) { return state, nil },
					stop: func(_ smartTUNTrialUnitObservation, started, valid bool) error {
						data, id, err := store.readSmartTUNFile(smartTUNTrialConfigFile)
						if !started || !valid || err != nil || id != credentialID || !bytes.Equal(data, secret) {
							return errors.New("retry lacked retained exact credential")
						}
						return nil
					},
				}
				if err := hostCoreStopWith(store, core, advance, service); err != nil {
					return err
				}
				if core.Stage != "stopped" {
					return errors.New("retry did not persist stopped Core")
				}
				if _, _, err := store.readSmartTUNFile(smartTUNTrialConfigFile); !errors.Is(err, os.ErrNotExist) {
					return errors.New("credential not retired after independently observed inactive Core")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Called only from the existing v7/v8/v9 real-kernel tests after their actual
// independent Off. Injection occurs at the existing idle/Core-observe callback
// inside terminal Clear, after its initial parent read. No production seam is
// added. The caller then performs a normal successful Clear as a positive control.
func hostTerminalClearReplacementRegression(t *testing.T, store *activationJournalDir, dir string, clear func(func() error) error) error {
	t.Helper()
	original, _, err := store.readJournal()
	if err != nil {
		return err
	}
	selected, err := selectTrialRecoveryLocked(store, "", "")
	if err != nil {
		return err
	}
	var changed any
	switch selected.version {
	case hostNativeJournalVersion:
		r := selected.hostNative
		r.Progress.Ingress.Deadline++
		changed = r
	case hostCoreJournalVersion:
		r := selected.hostCore
		r.Progress.Ingress.Deadline++
		changed = r
	case hostRouteJournalVersion:
		r := selected.hostRoute
		r.Progress.Ingress.Deadline++
		changed = r
	default:
		return errors.New("terminal-clear regression received an unexpected parent")
	}
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		return err
	}
	changedRaw = append(changedRaw, '\n')
	path := filepath.Join(dir, activationJournalFilename)
	for _, mode := range []string{"same_inode_changed_content", "new_inode_same_content"} {
		_, beforeID, err := store.readJournal()
		if err != nil {
			return err
		}
		replacement := original
		if mode == "same_inode_changed_content" {
			replacement = changedRaw
		}
		calls := 0
		var replacedID activationJournalFileIdentity
		err = clear(func() error {
			calls++
			if calls != 1 {
				return errors.New("terminal-clear mutation callback repeated")
			}
			if mode == "same_inode_changed_content" {
				if err := os.WriteFile(path, replacement, 0600); err != nil {
					return err
				}
			} else {
				tmp := filepath.Join(dir, "qa-terminal-parent-replacement")
				if err := os.WriteFile(tmp, replacement, 0600); err != nil {
					return err
				}
				if err := os.Rename(tmp, path); err != nil {
					return err
				}
			}
			got, id, err := store.readJournal()
			if err != nil || !bytes.Equal(got, replacement) {
				return errors.New("terminal-clear replacement was not visible")
			}
			if (mode == "same_inode_changed_content") != (id == beforeID) {
				return errors.New("terminal-clear fixture changed the wrong identity dimension")
			}
			replacedID = id
			return nil
		})
		if ErrorCode(err) != "activation_journal_conflict" || calls != 1 {
			return fmt.Errorf("terminal Clear did not reject %s after late observation: %v calls=%d", mode, err, calls)
		}
		got, id, err := store.readJournal()
		if err != nil || id != replacedID || !bytes.Equal(got, replacement) {
			return errors.New("terminal Clear unlinked or rewrote the replacement parent")
		}
		// Only the fixture owner restores its own original record.
		if err := store.writeJournal(original, &id); err != nil {
			return err
		}
		fmt.Printf("HOST_V%d_TERMINAL_CLEAR_%s_PRESERVED=PASS\n", selected.version, mode)
	}
	return nil
}
