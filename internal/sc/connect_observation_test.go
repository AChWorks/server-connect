package sc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fake core validates a configuration locally without a listener or any
// systemd/network effects. Each Connect case runs under the real private
// lifecycle lock; only its read-only service observation is injected.
func connectObservationFixture(t *testing.T, desired string, existingAuth bool) (*Manager, []byte, []byte, []byte) {
	t.Helper()
	m := New(t.TempDir(), "", 20807)
	if err := os.Chmod(m.Dir, 0700); err != nil {
		t.Fatal(err)
	}
	m.Core = filepath.Join(m.Dir, "test-only-sing-box")
	script := "#!/bin/sh\n[ \"$1\" = check ] || exit 42\nprintf 'checked' > '" + filepath.Join(m.Dir, "check-witness") + "'\nexit 0\n"
	if err := os.WriteFile(m.Core, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	p, err := ValidateSource([]byte("vless://11111111-1111-4111-8111-111111111111@192.0.2.40:443?type=tcp&security=none#fixture"), "")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.withLock(func() error {
		if err := put(filepath.Join(m.Dir, "profiles", p.ID+".json"), profile); err != nil {
			return err
		}
		return m.save(State{Version: 1, Desired: desired, Selected: p.ID, Port: m.Port})
	}); err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(m.Dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	runtime := []byte("EXISTING_RUNTIME_MUST_NOT_BE_OVERWRITTEN")
	if err := os.WriteFile(filepath.Join(m.Dir, "runtime.json"), runtime, 0600); err != nil {
		t.Fatal(err)
	}
	var auth []byte
	if existingAuth {
		auth = []byte(strings.Repeat("a", 48))
		if err := os.WriteFile(filepath.Join(m.Dir, "proxy-auth"), auth, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return m, state, runtime, auth
}

func TestConnectRejectsUnverifiedServiceBeforeRuntimeMutation(t *testing.T) {
	type observation struct {
		activity string
		err      error
	}
	cases := []struct {
		name, desired, wantCode string
		observations            []observation
		authExists              bool
		validationExpected      bool
	}{
		{"first-observation-fails-direct", "direct", "service_state_unavailable", []observation{{"unknown", errors.New("private-subprocess-secret")}}, false, false},
		{"first-observation-fails-proxy", "proxy", "service_state_unavailable", []observation{{"unknown", errors.New("private-subprocess-secret")}}, true, false},
		{"contradictory-active-error", "direct", "service_state_unavailable", []observation{{"active", errors.New("contradictory-active")}}, false, false},
		{"unsupported-status", "proxy", "service_state_unavailable", []observation{{"unparseable", nil}}, false, false},
		{"native-binary-untrusted", "direct", "service_binary_untrusted", []observation{{"unknown", Fault("service_binary_untrusted", "private-subprocess-secret")}}, false, false},
		{"unexpected-already-active", "direct", "service_conflict", []observation{{"active", nil}}, false, false},
		{"second-observation-fails-direct", "direct", "service_state_unavailable", []observation{{"inactive", nil}, {"unknown", errors.New("private-second-secret")}}, false, true},
		{"second-observation-fails-proxy", "proxy", "service_state_unavailable", []observation{{"failed", nil}, {"unknown", errors.New("private-second-secret")}}, true, true},
		{"second-contradictory-active", "direct", "service_state_unavailable", []observation{{"inactive", nil}, {"active", errors.New("private-second-secret")}}, false, true},
		{"second-unsupported-status", "proxy", "service_state_unavailable", []observation{{"inactive", nil}, {"unknown", nil}}, false, true},
		{"second-activity-turned-active", "direct", "service_conflict", []observation{{"inactive", nil}, {"active", nil}}, false, true},
		{"second-activity-turned-active-proxy", "proxy", "service_conflict", []observation{{"inactive", nil}, {"active", nil}}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, originalState, originalRuntime, originalAuth := connectObservationFixture(t, tc.desired, tc.authExists)
			callCount := 0
			err := m.withLock(func() error {
				return m.connectLocked(func() (string, error) {
					if callCount >= len(tc.observations) {
						t.Fatal("unexpected extra native service observation")
					}
					result := tc.observations[callCount]
					callCount++
					return result.activity, result.err
				})
			})
			if ErrorCode(err) != tc.wantCode || callCount != len(tc.observations) {
				t.Fatalf("unsafe activation path: code=%s calls=%d err=%v", ErrorCode(err), callCount, err)
			}
			if strings.Contains(err.Error(), "private-subprocess-secret") || strings.Contains(err.Error(), "private-second-secret") {
				t.Fatal("untrusted subprocess diagnostics leaked")
			}
			for file, original := range map[string][]byte{"state.json": originalState, "runtime.json": originalRuntime} {
				current, readErr := os.ReadFile(filepath.Join(m.Dir, file))
				if readErr != nil || !bytes.Equal(current, original) {
					t.Fatalf("%s was changed despite unverified service activity: %v", file, readErr)
				}
			}
			auth, readErr := os.ReadFile(filepath.Join(m.Dir, "proxy-auth"))
			if tc.authExists {
				if readErr != nil || !bytes.Equal(auth, originalAuth) {
					t.Fatalf("existing credentials changed on refusal: %v", readErr)
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatalf("new credentials were persisted before status confirmation: %v", readErr)
			}
			_, checkErr := os.Stat(filepath.Join(m.Dir, "check-witness"))
			if tc.validationExpected && checkErr != nil || !tc.validationExpected && !os.IsNotExist(checkErr) {
				t.Fatalf("wrong validation/observation sequence: %v", checkErr)
			}
		})
	}
}
