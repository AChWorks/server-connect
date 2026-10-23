package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// A diagnostic snapshot is deliberately private: no profile identifier,
// runtime bytes, local credentials or systemd invocation ID is serialized.
type diagnosticServiceInstance struct {
	PID        int
	Invocation string
}

type diagnosticProxyIdentity struct {
	SelectedID  string
	Port        int
	RuntimeHash [sha256.Size]byte
	AuthHash    [sha256.Size]byte
	Service     diagnosticServiceInstance
}

type diagnosticProxySnapshot struct {
	identity diagnosticProxyIdentity
	proxy    *url.URL
}

// systemd InvocationID distinguishes service restarts even if the selected
// profile, config bytes, listen port and recycled PID happen to be identical.
// Fail closed on absent/inconsistent evidence instead of guessing process age.
func parseDiagnosticServiceInstance(output []byte) (diagnosticServiceInstance, error) {
	var identity diagnosticServiceInstance
	if len(output) == 0 || len(output) > 8192 {
		return identity, errors.New("unavailable service-generation evidence")
	}
	fields := make(map[string]string, 3)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "ActiveState" && key != "MainPID" && key != "InvocationID") {
			return identity, errors.New("malformed service-generation evidence")
		}
		if _, duplicate := fields[key]; duplicate {
			return identity, errors.New("duplicate service-generation evidence")
		}
		fields[key] = value
	}
	if fields["ActiveState"] != "active" {
		return identity, errors.New("selected proxy service is not active")
	}
	pid, err := strconv.Atoi(fields["MainPID"])
	if err != nil || pid <= 0 {
		return identity, errors.New("missing service main process identity")
	}
	invocation := fields["InvocationID"]
	rawID, err := hex.DecodeString(invocation)
	if err != nil || len(rawID) != 16 {
		return identity, errors.New("missing service invocation identity")
	}
	return diagnosticServiceInstance{PID: pid, Invocation: strings.ToLower(invocation)}, nil
}

func queryDiagnosticServiceInstance() (diagnosticServiceInstance, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	result, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", DefaultUnit,
		"--property=ActiveState", "--property=MainPID", "--property=InvocationID").Output()
	if err != nil {
		return diagnosticServiceInstance{}, errors.New("service instance cannot be inspected")
	}
	return parseDiagnosticServiceInstance(result)
}

// captureDiagnosticProxy uses the existing narrow lifecycle lock to capture
// one coherent desired profile, installed service generation, private runtime,
// and selected loopback proxy credentials. It does NOT hold the lock while
// HTTP(S) requests run. Re-capturing before/after each request detects drift.
func (m *Manager) captureDiagnosticProxy() (diagnosticProxySnapshot, error) {
	return m.captureDiagnosticProxyWithService(m.verifyUnitOwnership, queryDiagnosticServiceInstance)
}

// The two systemd readers are injected only for disposable unit tests that
// exercise real private Manager state without installing any host service.
func (m *Manager) captureDiagnosticProxyWithService(verifyUnit func() error, serviceInstance func() (diagnosticServiceInstance, error)) (diagnosticProxySnapshot, error) {
	var snapshot diagnosticProxySnapshot
	err := m.withLock(func() error {
		state, err := m.load()
		if err != nil {
			return err
		}
		if state.Desired != "proxy" || !idPattern.MatchString(state.Selected) {
			return Fault("proxy_unavailable", "selected proxy is not active")
		}
		if err := verifyUnit(); err != nil {
			return Fault("proxy_unavailable", "selected service ownership unverified")
		}
		password, err := readRegular(filepath.Join(m.Dir, "proxy-auth"))
		if err != nil || len(password) != 48 {
			return Fault("proxy_unavailable", "selected proxy credentials unavailable")
		}
		runtime, err := readRegular(filepath.Join(m.Dir, "runtime.json"))
		if err != nil || len(runtime) == 0 {
			return Fault("proxy_unavailable", "selected runtime identity unavailable")
		}
		// A selected ID is not proof of the live outbound by itself.
		// Connect writes CoreConfig for that exact private profile and auth.
		profile, err := m.profile(state.Selected)
		if err != nil {
			return Fault("proxy_unavailable", "selected profile identity unavailable")
		}
		expected, err := CoreConfig(profile, state.Port, string(password))
		if err != nil || !bytes.Equal(expected, runtime) {
			return Fault("proxy_unavailable", "selected runtime/profile identity inconsistent")
		}
		service, err := serviceInstance()
		if err != nil {
			return Fault("proxy_unavailable", "selected service instance unverified")
		}
		snapshot.identity = diagnosticProxyIdentity{
			SelectedID:  state.Selected,
			Port:        state.Port,
			RuntimeHash: sha256.Sum256(runtime),
			AuthHash:    sha256.Sum256(password),
			Service:     service,
		}
		snapshot.proxy = &url.URL{
			Scheme: "http",
			Host:   "127.0.0.1:" + strconv.Itoa(state.Port),
			User:   url.UserPassword("sc", string(password)),
		}
		return nil
	})
	return snapshot, err
}
