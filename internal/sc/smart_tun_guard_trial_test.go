package sc

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func smartTUNCoreObservationExample(state string) smartTUNTrialUnitObservation {
	result := smartTUNTrialUnitObservation{
		identity: smartTUNTrialUnitIdentity{
			unitFile:   activationJournalFileIdentity{dev: 1, ino: 2},
			digestFile: activationJournalFileIdentity{dev: 1, ino: 3},
			unitSHA256: strings.Repeat("a", 64), digestSHA256: strings.Repeat("b", 64),
		},
		activeState: state, subState: "dead", result: "success",
	}
	if state == "active" {
		result.subState, result.mainPID, result.controlGroup = "running", 123, "/system.slice/"+smartTUNTrialUnit
	}
	if state == "failed" {
		result.subState, result.result = "failed", "signal"
	}
	return result
}

func TestSmartTUNCoreObservationRequiresCompleteOwnedQuiescenceEvidence(t *testing.T) {
	identity := smartTUNCoreObservationExample("inactive").identity
	raw := "Id=" + smartTUNTrialUnit + "\nLoadState=loaded\nFragmentPath=" +
		filepath.Join(trialGuardUnitDir, smartTUNTrialUnit) + "\nDropInPaths=\nTransient=no\nUnitFileState=static\n" +
		"ActiveState=inactive\nSubState=dead\nResult=success\nMainPID=0\nControlPID=0\nJob=\nControlGroup=\n"
	state, err := parseSmartTUNTrialUnitObservation([]byte(raw), identity)
	if err != nil || !state.stopped() || state.identity != identity {
		t.Fatalf("complete inactive evidence rejected: %+v %v", state, err)
	}
	for name, bad := range map[string]string{
		"missing cgroup":      strings.Replace(raw, "ControlGroup=\n", "", 1),
		"missing control PID": strings.Replace(raw, "ControlPID=0\n", "", 1),
		"missing job":         strings.Replace(raw, "Job=\n", "", 1),
		"duplicate state":     raw + "ActiveState=inactive\n",
		"unknown field":       raw + "Other=0\n",
		"malformed line":      raw + "unknown\n",
		"different unit":      strings.Replace(raw, "Id="+smartTUNTrialUnit, "Id=foreign.service", 1),
		"different fragment":  strings.Replace(raw, "FragmentPath=/etc/", "FragmentPath=/run/", 1),
		"drop-in":             strings.Replace(raw, "DropInPaths=\n", "DropInPaths=/run/override.conf\n", 1),
		"transient":           strings.Replace(raw, "Transient=no", "Transient=yes", 1),
		"autostart":           strings.Replace(raw, "UnitFileState=static", "UnitFileState=enabled", 1),
		"unknown state":       strings.Replace(raw, "ActiveState=inactive", "ActiveState=reloading", 1),
		"empty substate":      strings.Replace(raw, "SubState=dead", "SubState=", 1),
		"empty result":        strings.Replace(raw, "Result=success", "Result=", 1),
		"noncanonical PID":    strings.Replace(raw, "MainPID=0", "MainPID=00", 1),
		"negative PID":        strings.Replace(raw, "ControlPID=0", "ControlPID=-1", 1),
		"oversized PID":       strings.Replace(raw, "MainPID=0", "MainPID=4294967296", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseSmartTUNTrialUnitObservation([]byte(bad), identity); err == nil {
				t.Fatal("ambiguous ownership/work evidence accepted")
			}
		})
	}
	for name, changed := range map[string]string{
		"tracked main":                           strings.Replace(raw, "MainPID=0", "MainPID=123", 1),
		"tracked control":                        strings.Replace(raw, "ControlPID=0", "ControlPID=456", 1),
		"queued job":                             strings.Replace(raw, "Job=\n", "Job=42\n", 1),
		"zero tracked PIDs with residual cgroup": strings.Replace(raw, "ControlGroup=\n", "ControlGroup=/system.slice/"+smartTUNTrialUnit+"\n", 1),
		"pinned dead resources":                  strings.Replace(raw, "SubState=dead", "SubState=dead-resources-pinned", 1),
	} {
		t.Run(name, func(t *testing.T) {
			observed, err := parseSmartTUNTrialUnitObservation([]byte(changed), identity)
			if err != nil || observed.stopped() {
				t.Fatalf("live/uncertain work treated as stopped: %+v %v", observed, err)
			}
		})
	}
}

func TestSmartTUNCoreStopNormalizesOnlyTheSameQuiescentFailedUnit(t *testing.T) {
	active := smartTUNCoreObservationExample("active")
	failed := smartTUNCoreObservationExample("failed")
	inactive := smartTUNCoreObservationExample("inactive")
	change := func(base smartTUNTrialUnitObservation, edit func(*smartTUNTrialUnitObservation)) smartTUNTrialUnitObservation {
		edit(&base)
		return base
	}
	cases := []struct {
		name         string
		original     smartTUNTrialUnitObservation
		observations []smartTUNTrialUnitObservation
		commands     string
		wantOK       bool
	}{
		{"ordinary stop", active, []smartTUNTrialUnitObservation{active, inactive}, "stop", true},
		{"already inactive", inactive, []smartTUNTrialUnitObservation{inactive, inactive}, "stop", true},
		{"SIGKILL failure survives stop ACK", failed, []smartTUNTrialUnitObservation{failed, failed, inactive}, "stop,reset-failed", true},
		{"dies during stop", active, []smartTUNTrialUnitObservation{active, failed, inactive}, "stop,reset-failed", true},
		{"failed retained after reset", failed, []smartTUNTrialUnitObservation{failed, failed, failed}, "stop,reset-failed", false},
		{"core still active", active, []smartTUNTrialUnitObservation{active, active}, "stop", false},
		{"unexpected new start", inactive, []smartTUNTrialUnitObservation{active}, "", false},
		{"queued start before stop", active, []smartTUNTrialUnitObservation{change(active, func(s *smartTUNTrialUnitObservation) { s.job = "17" })}, "", false},
		{"failed main PID", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.mainPID = 123 })}, "stop", false},
		{"failed control PID", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.controlPID = 456 })}, "stop", false},
		{"failed queued job", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.job = "18" })}, "stop", false},
		{"failed zero PIDs residual cgroup", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.controlGroup = "/system.slice/" + smartTUNTrialUnit })}, "stop", false},
		{"failed wrong substate", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.subState = "stop-sigkill" })}, "stop", false},
		{"failed contradictory result", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.result = "success" })}, "stop", false},
		{"inactive residual cgroup", active, []smartTUNTrialUnitObservation{active, change(inactive, func(s *smartTUNTrialUnitObservation) { s.controlGroup = "/system.slice/" + smartTUNTrialUnit })}, "stop", false},
		{"unit replaced before stop", failed, []smartTUNTrialUnitObservation{change(failed, func(s *smartTUNTrialUnitObservation) { s.identity.unitFile.ino++ })}, "", false},
		{"identical bytes replacement after stop", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.identity.unitFile.ino++ })}, "stop", false},
		{"digest replacement after stop", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.identity.digestFile.ino++ })}, "stop", false},
		{"content changed after stop", failed, []smartTUNTrialUnitObservation{failed, change(failed, func(s *smartTUNTrialUnitObservation) { s.identity.unitSHA256 = strings.Repeat("c", 64) })}, "stop", false},
		{"replacement after reset", failed, []smartTUNTrialUnitObservation{failed, failed, change(inactive, func(s *smartTUNTrialUnitObservation) { s.identity.unitFile.ino++ })}, "stop,reset-failed", false},
		{"new work after reset", failed, []smartTUNTrialUnitObservation{failed, failed, active}, "stop,reset-failed", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.original
			reads := 0
			var commands []string
			err := stopSmartTUNTrialCoreWith(original, true, true, func() (smartTUNTrialUnitObservation, error) {
				if reads >= len(tc.observations) {
					t.Fatal("unexpected extra state observation")
				}
				observed := tc.observations[reads]
				reads++
				return observed, nil
			}, func(action string) error { commands = append(commands, action); return nil })
			if (err == nil) != tc.wantOK || strings.Join(commands, ",") != tc.commands || reads != len(tc.observations) || original != tc.original {
				t.Fatalf("incorrect stop authority: commands=%v reads=%d err=%v", commands, reads, err)
			}
		})
	}
}

func TestSmartTUNCoreStopPreservesUncertaintyAfterPartialCommandOrQueryFailure(t *testing.T) {
	for _, failure := range []string{"pre-query", "stop", "post-stop-query", "reset-failed", "post-reset-query"} {
		t.Run(failure, func(t *testing.T) {
			original := smartTUNCoreObservationExample("failed")
			current := original
			reads := 0
			var commands []string
			injected := errors.New("lost acknowledgement or query")
			err := stopSmartTUNTrialCoreWith(original, true, true, func() (smartTUNTrialUnitObservation, error) {
				reads++
				if (reads == 1 && failure == "pre-query") || (reads == 2 && failure == "post-stop-query") || (reads == 3 && failure == "post-reset-query") {
					return smartTUNTrialUnitObservation{}, injected
				}
				return current, nil
			}, func(action string) error {
				commands = append(commands, action)
				if action == "reset-failed" {
					current = smartTUNCoreObservationExample("inactive")
				}
				if failure == action {
					// A command may have taken effect despite lost acknowledgement.
					current = smartTUNCoreObservationExample("inactive")
					return injected
				}
				return nil
			})
			if !errors.Is(err, injected) {
				t.Fatalf("partial outcome incorrectly cleared: commands=%v err=%v", commands, err)
			}
			want := "stop,reset-failed"
			if failure == "pre-query" {
				want = ""
			}
			if failure == "stop" || failure == "post-stop-query" {
				want = "stop"
			}
			if strings.Join(commands, ",") != want {
				t.Fatalf("mutation continued after uncertainty: %v", commands)
			}
		})
	}
}

func TestSmartTUNCoreNormalizationDoesNotLaunderOriginalCredentialState(t *testing.T) {
	original := smartTUNCoreObservationExample("failed")
	current := original
	if err := stopSmartTUNTrialCoreWith(original, true, true,
		func() (smartTUNTrialUnitObservation, error) { return current, nil },
		func(action string) error {
			if action == "reset-failed" {
				current = smartTUNCoreObservationExample("inactive")
			}
			return nil
		}); err != nil {
		t.Fatal(err)
	}
	if original.activeState != "failed" || !current.stopped() {
		t.Fatal("normalization rewrote the original credential evidence")
	}
	for name, record := range map[string]smartTUNTrialJournal{"legacy": trialV4Example(), "native": nativeTrialExample(false)} {
		t.Run(name, func(t *testing.T) {
			record.CoreStartAttempted = true
			if err := smartTUNTrialCredentialRecoveryCheck(record, original.activeState, false, false); err == nil {
				t.Fatal("failed core normalization authorized a missing started credential")
			}
			if err := smartTUNTrialCredentialRecoveryCheck(record, original.activeState, true, true); err != nil {
				t.Fatalf("valid started credential refused solely because original core failed: %v", err)
			}
		})
	}
}

func TestSmartTUNCoreFailedEvidenceSurvivesRepeatedUntrustedNormalization(t *testing.T) {
	for _, started := range []bool{false, true} {
		for _, credentialValid := range []bool{false, true} {
			if started && credentialValid {
				continue
			}
			current := smartTUNCoreObservationExample("failed")
			for tick := 0; tick < 2; tick++ {
				var commands []string
				err := stopSmartTUNTrialCoreWith(current, started, credentialValid,
					func() (smartTUNTrialUnitObservation, error) { return current, nil },
					func(action string) error {
						commands = append(commands, action)
						if action == "reset-failed" {
							current = smartTUNCoreObservationExample("inactive")
						}
						return nil
					})
				wantCommands := ""
				if started {
					wantCommands = "stop"
				}
				if err == nil || current.activeState != "failed" || strings.Join(commands, ",") != wantCommands {
					t.Fatalf("failed evidence laundered on tick %d (start=%v credential=%v): commands=%v state=%+v err=%v", tick, started, credentialValid, commands, current, err)
				}
			}
		}
	}
}

func TestSmartTUNCoreNoStartConflictSurvivesRepeatedRecoveryTicks(t *testing.T) {
	for kind, record := range map[string]smartTUNTrialJournal{"legacy": trialV4Example(), "native": nativeTrialExample(false)} {
		record.CoreStartAttempted = false
		for _, activity := range []string{"active", "activating", "failed"} {
			for _, credential := range []struct {
				name           string
				present, valid bool
			}{
				{"valid", true, true}, {"absent", false, false},
			} {
				t.Run(kind+"/"+activity+"/"+credential.name, func(t *testing.T) {
					current := smartTUNCoreObservationExample(activity)
					if activity == "activating" {
						current.subState, current.mainPID, current.controlGroup = "start", 123, "/system.slice/"+smartTUNTrialUnit
					}
					conflict := current
					for tick := 0; tick < 2; tick++ {
						var commands []string
						err := stopSmartTUNTrialCoreWith(current, record.CoreStartAttempted, credential.valid,
							func() (smartTUNTrialUnitObservation, error) { return current, nil },
							func(action string) error {
								commands = append(commands, action)
								// This models the old bug: stop erases activity, allowing
								// the next tick to accept the unchanged no-start journal.
								current = smartTUNCoreObservationExample("inactive")
								return nil
							})
						if err == nil || len(commands) != 0 || current != conflict {
							t.Fatalf("no-start evidence erased on tick %d: commands=%v state=%+v err=%v", tick, commands, current, err)
						}
						if err := smartTUNTrialCredentialRecoveryCheck(record, current.activeState, credential.present, credential.valid); err == nil {
							t.Fatal("conflicting activity became acceptable pre-start evidence")
						}
					}
				})
			}
		}
	}
}

func TestSmartTUNCoreNoStartRequiresBothOwnedObservationsAlreadyStopped(t *testing.T) {
	clean := smartTUNCoreObservationExample("inactive")
	active := smartTUNCoreObservationExample("active")
	dirty := clean
	dirty.controlGroup = "/system.slice/" + smartTUNTrialUnit
	queued := clean
	queued.job = "19"
	replaced := clean
	replaced.identity.unitFile.ino++
	for _, credentialValid := range []bool{false, true} {
		for _, tc := range []struct {
			name            string
			original, fresh smartTUNTrialUnitObservation
			wantOK          bool
		}{
			{"clean", clean, clean, true},
			{"original activity", active, clean, false},
			{"new activity", clean, active, false},
			{"original residual work", dirty, clean, false},
			{"new residual work", clean, dirty, false},
			{"original queued job", queued, clean, false},
			{"new queued job", clean, queued, false},
			{"unit replacement", clean, replaced, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				reads, commands := 0, 0
				err := stopSmartTUNTrialCoreWith(tc.original, false, credentialValid,
					func() (smartTUNTrialUnitObservation, error) { reads++; return tc.fresh, nil },
					func(string) error { commands++; return nil })
				if (err == nil) != tc.wantOK || reads != 1 || commands != 0 {
					t.Fatalf("no-start recovery mutated or lost two-snapshot proof: reads=%d commands=%d err=%v", reads, commands, err)
				}
			})
		}
	}
}

func TestSmartTUNCoreStartedCredentialConflictStillContains(t *testing.T) {
	for kind, record := range map[string]smartTUNTrialJournal{"legacy": trialV4Example(), "native": nativeTrialExample(false)} {
		record.CoreStartAttempted = true
		for _, credential := range []struct {
			name    string
			present bool
		}{{"missing", false}, {"tampered", true}} {
			t.Run(kind+"/"+credential.name, func(t *testing.T) {
				current := smartTUNCoreObservationExample("active")
				for tick := 0; tick < 2; tick++ {
					original := current
					var commands []string
					err := stopSmartTUNTrialCoreWith(original, record.CoreStartAttempted, false,
						func() (smartTUNTrialUnitObservation, error) { return current, nil },
						func(action string) error {
							commands = append(commands, action)
							current = smartTUNCoreObservationExample("inactive")
							return nil
						})
					if err != nil || !current.stopped() || strings.Join(commands, ",") != "stop" {
						t.Fatalf("started core containment changed on tick %d: commands=%v err=%v", tick, commands, err)
					}
					if err := smartTUNTrialCredentialRecoveryCheck(record, original.activeState, credential.present, false); err == nil {
						t.Fatal("containment cleared the durable credential conflict")
					}
				}
			})
		}
	}
}

func trialV4Example() smartTUNTrialJournal {
	return smartTUNTrialJournal{
		Version: smartTUNTrialVersion, Revision: 1, OperationID: strings.Repeat("a", 32),
		IntentType: smartTUNTrialIntent, Phase: "trial_pending", CreatedUnix: 1760000000,
		BootID: "11111111-2222-3333-4444-555555555555", DeadlineUptimeSec: 12345,
		ProfileID: "0123456789abcdef", EndpointIP: "10.254.72.2", ManagementPeerIP: "10.254.72.2",
		TunnelInterface: "sctunqa0", UnderlayInterface: "scqaedge0",
		ConfigSHA256: strings.Repeat("1", 64), BaselineSHA256: strings.Repeat("2", 64),
	}
}

func TestSmartTUNJournalCanonicalPhasesAndMinimalReceipt(t *testing.T) {
	pending := trialV4Example()
	started := pending
	started.CoreStartAttempted = true
	recovered := started
	recovered.Phase, recovered.Revision = "trial_recovered", 2
	precredentialRecovery := pending
	precredentialRecovery.Phase, precredentialRecovery.Revision = "trial_recovered", 2
	for _, record := range []smartTUNTrialJournal{pending, started, recovered, precredentialRecovery} {
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeSmartTUNTrial(raw)
		if err != nil || decoded != record {
			t.Fatalf("valid v4 record: %v", err)
		}
		receipt := smartTUNReceipt(record, record.Phase == "trial_pending", record.Phase == "trial_recovered")
		if receipt.ActivationReady || receipt.VPNVerified || !receipt.ExperimentOnly ||
			receipt.RecoveryVerified != (record.Phase == "trial_recovered") {
			t.Fatalf("unverified production readiness: %+v", receipt)
		}
	}
}

func TestSmartTUNJournalInvalidResourceIdentityAndPhaseRejected(t *testing.T) {
	cases := []struct {
		name string
		edit func(*smartTUNTrialJournal)
	}{
		{"future version", func(r *smartTUNTrialJournal) { r.Version = 5 }},
		{"legacy version collision", func(r *smartTUNTrialJournal) { r.Version = 3 }},
		{"unknown intent", func(r *smartTUNTrialJournal) { r.IntentType = "route" }},
		{"wrong pending revision", func(r *smartTUNTrialJournal) { r.Revision = 2 }},
		{"recovered with pending revision", func(r *smartTUNTrialJournal) { r.Phase = "trial_recovered" }},
		{"unverified active state", func(r *smartTUNTrialJournal) { r.Phase = "active_verified" }},
		{"bad operation", func(r *smartTUNTrialJournal) { r.OperationID = "not-an-id" }},
		{"bad profile", func(r *smartTUNTrialJournal) { r.ProfileID = "user-name" }},
		{"bad boot", func(r *smartTUNTrialJournal) { r.BootID = "different" }},
		{"deadline absent", func(r *smartTUNTrialJournal) { r.DeadlineUptimeSec = 0 }},
		{"unsafe interface", func(r *smartTUNTrialJournal) { r.TunnelInterface = "../x" }},
		{"overlapping interfaces", func(r *smartTUNTrialJournal) { r.UnderlayInterface = "sctunqa0" }},
		{"loopback underlay", func(r *smartTUNTrialJournal) { r.UnderlayInterface = "lo" }},
		{"DNS endpoint", func(r *smartTUNTrialJournal) { r.EndpointIP = "example.org" }},
		{"loopback endpoint", func(r *smartTUNTrialJournal) { r.EndpointIP = "127.0.0.1" }},
		{"multicast management", func(r *smartTUNTrialJournal) { r.ManagementPeerIP = "224.0.0.1" }},
		{"linklocal", func(r *smartTUNTrialJournal) { r.EndpointIP = "169.254.1.2" }},
		{"bad hash", func(r *smartTUNTrialJournal) { r.BaselineSHA256 = "00" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			record := trialV4Example()
			tc.edit(&record)
			raw, _ := json.Marshal(record)
			if _, err := decodeSmartTUNTrial(raw); err == nil {
				t.Fatal("invalid persisted operation accepted")
			}
		})
	}
}

func TestSmartTUNJournalRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	raw, _ := json.Marshal(trialV4Example())
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), []byte(" {}")...),
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false,`, "", 1)),
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false`, `"core_start_attempted":null`, 1)),
		[]byte(strings.Replace(string(raw), `"core_start_attempted":false`, `"core_start_attempted":"false"`, 1)),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unknown":false}`)...),
		append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"version":4}`)...),
		[]byte("[]"), []byte("null"), []byte(""), []byte("{"),
	} {
		if _, err := decodeSmartTUNTrial(bad); err == nil {
			t.Fatalf("accepted invalid persisted JSON %q", bad)
		}
	}
}

func TestSmartTUNActiveUnitWithoutDurableStartIntentCannotRemainPending(t *testing.T) {
	record := trialV4Example()
	for _, tc := range []struct {
		name                  string
		attempted             bool
		unit                  string
		credential, bootValid bool
		uptime                int64
		want                  bool
	}{
		{"unauthorized active before durable start", false, "active", true, true, 10, false},
		{"unauthorized activating before durable start", false, "activating", true, true, 10, false},
		{"legitimate active before deadline", true, "active", true, true, 10, true},
		{"legitimate activating before deadline", true, "activating", true, true, 10, true},
		{"missing credential after start", true, "active", false, true, 10, false},
		{"stopped core", true, "inactive", true, true, 10, false},
		{"failed core", true, "failed", true, true, 10, false},
		{"boot changed", true, "active", true, false, 10, false},
		{"deadline reached", true, "active", true, true, record.DeadlineUptimeSec, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record.CoreStartAttempted = tc.attempted
			got := smartTUNTrialMayRemainPending(record, tc.unit, tc.credential, tc.bootValid, tc.uptime)
			if got != tc.want {
				t.Fatalf("unsafe pending admission: got=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestSmartTUNCredentialRecoveryNeverLosesStartIntentOnRepeatedGuardTicks(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		started, present, matches bool
		beforeStop                string
		accept                    bool
	}{
		{"journal-first SIGKILL before credentials", false, false, false, "inactive", true},
		{"crash before core start with staged credential", false, true, true, "inactive", true},
		{"started core with original credential", true, true, true, "active", true},
		{"stopped failed core with original credential", true, true, true, "failed", true},
		{"missing credential after core start, first timer", true, false, false, "active", false},
		{"missing credential after core start, next timer", true, false, false, "inactive", false},
		{"changed credential after core start, next timer", true, true, false, "inactive", false},
		{"no durable start intent but unexpected core", false, true, true, "active", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := trialV4Example()
			r.CoreStartAttempted = tc.started
			err := smartTUNTrialCredentialRecoveryCheck(r, tc.beforeStop, tc.present, tc.matches)
			if tc.accept != (err == nil) {
				t.Fatalf("unsafe credential recovery decision: accepted=%v err=%v", err == nil, err)
			}
		})
	}
}

func TestSmartTUNPendingBlocksGenericStatusAndLegacyControl(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	if phase, err := m.pendingSmartTUNTrial(); err != nil || phase != "" {
		t.Fatalf("absent journal changed status: %q %v", phase, err)
	}
	raw, _ := json.Marshal(trialV4Example())
	if err := os.WriteFile(filepath.Join(dir, activationJournalFilename), raw, 0600); err != nil {
		t.Fatal(err)
	}
	phase, err := m.pendingSmartTUNTrial()
	if err != nil || phase != "trial_pending" {
		t.Fatalf("cannot recognize pending trial: %q %v", phase, err)
	}
	status, err := m.statusWithService(func() (string, error) {
		t.Fatal("generic status must not inspect proxy and claim Direct while TUN trial pending")
		return "", nil
	}, func() error { t.Fatal("must not verify unrelated proxy unit"); return nil })
	if ErrorCode(err) != "guard_pending" || status.Observed != "smart_tun_trial_pending" ||
		status.Health != "guarded_trial_unconfirmed" {
		t.Fatalf("false Direct status while guarded TUN pending: %+v %v", status, err)
	}
	if err := m.withLock(func() error {
		return m.connectLocked(func() (string, error) {
			t.Fatal("must not activate Proxy Only during TUN trial")
			return "inactive", nil
		})
	}); ErrorCode(err) != "guard_pending" {
		t.Fatalf("proxy Connect not blocked: %v", err)
	}
	if err := m.Select("0123456789abcdef"); ErrorCode(err) != "guard_pending" {
		t.Fatalf("profile Select not blocked: %v", err)
	}
}

func TestSmartTUNPendingRejectsCorruptAndUntrustedLocalJournal(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m := New(dir, DefaultCore, DefaultPort)
	if err := m.prepare(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, activationJournalFilename)
	if err := os.WriteFile(path, []byte(`{"version":4}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pendingSmartTUNTrial(); err == nil {
		t.Fatal("accepted truncated v4 journal")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pendingSmartTUNTrial(); err == nil {
		t.Fatal("accepted untrusted symlink journal")
	}
}

func TestSmartTUNClearCredentialConflictBeforeGuardDisarm(t *testing.T) {
	dir := privateJournalTempDir(t)
	m := New(dir, DefaultCore, DefaultPort)
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		record := trialV4Example()
		record.Phase, record.Revision = "trial_recovered", 2
		if _, err := smartTUNCredentialForCleanupLocked(store, record); err != nil {
			t.Fatalf("precredential crash must permit absent config: %v", err)
		}
		record.CoreStartAttempted = true
		if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("missing start credential must block cleanup intent: %v", err)
		}
		original := []byte("unchanged guarded credential")
		record.ConfigSHA256 = sha256Hex(original)
		if err := store.writeSmartTUNFile(smartTUNTrialConfigFile, original, nil); err != nil {
			return err
		}
		identity, err := smartTUNCredentialForCleanupLocked(store, record)
		if err != nil || identity == nil {
			t.Fatalf("exact recovered credential rejected: %v", err)
		}
		// The same present credential remains valid once cleanup is durable.
		record.Phase, record.Revision = "trial_cleanup_pending", 4
		if err := writeSmartTUNTrialLocked(store, record, nil); err != nil {
			return err
		}
		journalIdentity, err := reloadSmartTUNTrialLocked(store, record)
		if err != nil {
			return err
		}
		if err := store.removeSmartTUNCredential(journalIdentity, record, identity, syscall.Fsync); err != nil {
			return err
		}
		if identity, err := smartTUNCredentialForCleanupLocked(store, record); err != nil || identity != nil {
			t.Fatalf("durable cleanup did not permit removed credential: %v", err)
		}
		// Replaying the OLD recovered phase must still refuse missing bytes.
		record.Phase, record.Revision = "trial_recovered", 2
		if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
			t.Fatalf("old phase silently accepted unexplained credential loss: %v", err)
		}
		path := filepath.Join(dir, smartTUNTrialConfigFile)
		if err := os.WriteFile(path, []byte("changed configuration"), 0600); err != nil {
			return err
		}
		for _, phase := range []string{"trial_recovered", "trial_cleanup_pending"} {
			record.Phase = phase
			if _, err := smartTUNCredentialForCleanupLocked(store, record); ErrorCode(err) != "trial_resource_conflict" {
				t.Fatalf("phase %s accepted replaced credential: %v", phase, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The installed product API is narrower than the offline compiler. It only
// admits the exact IPv4 QA fixture, or its one explicit synthetic IPv6
// extension; no untrusted public prefix or arbitrary host can be applied.
func TestSmartTUNTrialFixtureScopeRejectsPartialAndBroaderIPv6(t *testing.T) {
	base := func() SmartTUNCandidateOptions {
		return SmartTUNCandidateOptions{
			TunnelInterface: "sctunqa0", UnderlayInterface: "scqaedge0",
			TunnelIPv4: "172.31.99.1/30", DomesticCIDRs: []string{"5.22.0.10/32"},
			ProtectedCIDRs: []string{"10.254.72.0/30"},
		}
	}
	dual := func() SmartTUNCandidateOptions {
		o := base()
		o.TunnelIPv6 = "fd73:99::1/64"
		o.DomesticIPv6CIDRs = []string{"2001:db8:5::/64"}
		o.IPv6Exceptions = []SmartTUNCIDRException{
			{CIDR: "2001:db8:5::10/128", Via: "vpn"},
			{CIDR: "2001:db8:8::9/128", Via: "direct"},
		}
		return o
	}
	if !smartTUNTrialFixturePolicySupported(base()) || !smartTUNTrialFixturePolicySupported(dual()) {
		t.Fatal("exact disposable IPv4 / dual-stack fixtures were refused")
	}
	for _, tc := range []struct {
		name string
		edit func(*SmartTUNCandidateOptions)
	}{
		{"missing IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "" }},
		{"missing IPv6 domestic", func(o *SmartTUNCandidateOptions) { o.DomesticIPv6CIDRs = nil }},
		{"extra IPv6 domestic", func(o *SmartTUNCandidateOptions) {
			o.DomesticIPv6CIDRs = append(o.DomesticIPv6CIDRs, "2001:db8:9::/64")
		}},
		{"wrong IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "fd73:98::1/64" }},
		{"public IPv6 TUN", func(o *SmartTUNCandidateOptions) { o.TunnelIPv6 = "2001:db8:ffff::1/64" }},
		{"missing VPN override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions = o.IPv6Exceptions[1:] }},
		{"missing Direct override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions = o.IPv6Exceptions[:1] }},
		{"wrong VPN override", func(o *SmartTUNCandidateOptions) { o.IPv6Exceptions[0].CIDR = "2001:db8:5::11/128" }},
		{"swapped override precedence", func(o *SmartTUNCandidateOptions) {
			o.IPv6Exceptions[0], o.IPv6Exceptions[1] = o.IPv6Exceptions[1], o.IPv6Exceptions[0]
		}},
		{"protected IPv6 stranger", func(o *SmartTUNCandidateOptions) { o.ProtectedIPv6CIDRs = []string{"2001:db8:ffff::42/128"} }},
		{"foreign IPv4 exception", func(o *SmartTUNCandidateOptions) {
			o.Exceptions = []SmartTUNCIDRException{{CIDR: "8.8.8.8/32", Via: "direct"}}
		}},
		{"extra IPv4 Direct", func(o *SmartTUNCandidateOptions) { o.DomesticCIDRs = append(o.DomesticCIDRs, "8.8.8.8/32") }},
		{"different underlay", func(o *SmartTUNCandidateOptions) { o.UnderlayInterface = "enp1s0" }},
		{"domain sniff", func(o *SmartTUNCandidateOptions) {
			o.DomainExceptions = []SmartTUNDomainException{{Domain: "example.com", Via: "vpn"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := dual()
			tc.edit(&o)
			if smartTUNTrialFixturePolicySupported(o) {
				t.Fatal("broadened real product TUN trial fixture")
			}
		})
	}
	o := base()
	o.TunnelIPv6 = "fd73:99::1/64"
	if smartTUNTrialFixturePolicySupported(o) {
		t.Fatal("partially specified IPv6 fixture accepted")
	}
}

func TestSmartTUNTrialRefusesNoninstalledContextBeforeAnySystemctl(t *testing.T) {
	m := New(t.TempDir(), DefaultCore, DefaultPort)
	_, err := m.BeginSmartTUNTrial(SmartTUNCandidateOptions{}, "", 600, "")
	if ErrorCode(err) != "trial_unsupported" {
		t.Fatalf("trial on arbitrary state directory did not fail closed: %v", err)
	}
}

// Existing foreign nftables owners must be in the protected baseline, not
// silently rejected, stripped, ignored or treated as product-owned. The
// counter normalization from the native PR #66 preflight remains relevant.
func TestSmartTUNSnapshotIncludesPreexistingNftablesOwners(t *testing.T) {
	firewall, err := decodeNFTSnapshot([]byte(exampleNFT))
	if err != nil || firewall.ObjectCount == 0 {
		t.Fatalf("invalid foreign firewall fixture: %+v %v", firewall, err)
	}
	host := driftFixture()
	host.Mode = "observation_with_nftables"
	host.Firewall = &firewall
	before, err := smartTUNTrialSnapshot(host)
	if err != nil || !journalHex64.MatchString(before) {
		t.Fatalf("complete foreign-owner guest snapshot rejected: %v", err)
	}
	trafficOnly := strings.Replace(exampleNFT, `"packets":12`, `"packets":2000`, 1)
	trafficOnly = strings.Replace(trafficOnly, `"bytes":8192`, `"bytes":500000`, 1)
	trafficObservation, err := decodeNFTSnapshot([]byte(trafficOnly))
	if err != nil {
		t.Fatal(err)
	}
	host.Firewall = &trafficObservation
	unchanged, err := smartTUNTrialSnapshot(host)
	if err != nil || unchanged != before {
		t.Fatalf("traffic-only counters caused false firewall baseline drift: %v", err)
	}
	foreignMutation := strings.Replace(exampleNFT, "8.8.8.8", "9.9.9.9", 1)
	mutated, err := decodeNFTSnapshot([]byte(foreignMutation))
	if err != nil {
		t.Fatal(err)
	}
	host.Firewall = &mutated
	changed, err := smartTUNTrialSnapshot(host)
	if err != nil || changed == before {
		t.Fatalf("foreign firewall rule drift was not detected: %v", err)
	}
	host.Firewall = nil
	if _, err := smartTUNTrialSnapshot(host); err == nil {
		t.Fatal("accepted missing native firewall evidence")
	}
}
