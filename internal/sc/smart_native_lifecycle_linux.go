//go:build linux

package sc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const nativeSmartUnit = "server-connect-native-tun.service"
const nativeConfigFile = "native-tun.json"
const nativeSessionFile = "native-session.json"
const nativeUnitPath = "/etc/systemd/system/server-connect-native-tun.service"

// This small persisted receipt is written before starting the official Core.
// It authorizes only the fixed native policy slots, not global route repair.
type NativeSession struct {
	Version       int    `json:"version"`
	Selected      string `json:"selected"`
	InterfaceName string `json:"tunnel_if"`
	UnderlayIF    string `json:"underlay_if"`
	ConfigSHA256  string `json:"config_sha256"`
}
type NativeConnectionStatus struct {
	Desired              string `json:"desired"`
	Observed             string `json:"observed"`
	Selected             string `json:"selected_profile_id"`
	RecoveryClaimPresent bool   `json:"recovery_claim_present"`
	CoreUnit             string `json:"core_unit"`
	NativePolicyVerified bool   `json:"native_policy_verified"`
	SelectedVPNPathProof string `json:"selected_vpn_path_proof"`
}

func (m *Manager) readNativeSession() (NativeSession, error) {
	raw, err := readRegular(filepath.Join(m.Dir, nativeSessionFile))
	if err != nil {
		return NativeSession{}, err
	}
	if len(raw) == 0 || len(raw) > 4096 || rejectAmbiguousJournalJSON(raw) != nil {
		return NativeSession{}, Fault("invalid_state", "invalid native recovery claim")
	}
	var session NativeSession
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&session) != nil || !errors.Is(decoder.Decode(&trailing), io.EOF) ||
		session.Version != 1 || !idPattern.MatchString(session.Selected) ||
		!smartTUNDeviceName.MatchString(session.InterfaceName) ||
		!smartTUNDeviceName.MatchString(session.UnderlayIF) ||
		session.InterfaceName == session.UnderlayIF ||
		session.InterfaceName == "lo" || session.UnderlayIF == "lo" || len(session.ConfigSHA256) != 64 {
		return NativeSession{}, Fault("invalid_state", "invalid native recovery claim")
	}
	if _, err := hex.DecodeString(session.ConfigSHA256); err != nil {
		return NativeSession{}, Fault("invalid_state", "invalid native config digest")
	}
	return session, nil
}
func (m *Manager) validateNativeSessionConfig(session NativeSession) error {
	raw, err := readRegular(filepath.Join(m.Dir, nativeConfigFile))
	if err != nil {
		return Fault("invalid_state", "native config is missing")
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != session.ConfigSHA256 {
		return Fault("invalid_state", "native config has changed")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return Fault("invalid_state", "native config is malformed")
	}
	var inbounds []map[string]json.RawMessage
	if json.Unmarshal(obj["inbounds"], &inbounds) != nil || len(inbounds) != 1 {
		return Fault("invalid_state", "native policy inbounds are invalid")
	}
	var kind, name string
	if json.Unmarshal(inbounds[0]["type"], &kind) != nil ||
		json.Unmarshal(inbounds[0]["interface_name"], &name) != nil ||
		kind != "tun" || name != session.InterfaceName {
		return Fault("invalid_state", "native policy differs from recovery claim")
	}
	return nil
}
func (m *Manager) nativeUnitOwnership() error {
	if os.Geteuid() != 0 || m.Dir != DefaultDir || m.Core != DefaultCore {
		return Fault("ownership_required", "installed native lifecycle requires root and owned paths")
	}
	marker, err := readTrustedRootFile(filepath.Join(managedPrefix, ".owner"))
	if err != nil || strings.TrimSpace(string(marker)) != "AChWorks/server-connect" {
		return Fault("service_conflict", "native installation owner unavailable")
	}
	unit, err := readTrustedRootFile(nativeUnitPath)
	if err != nil {
		return Fault("service_conflict", "native service file untrusted")
	}
	digest, err := readTrustedRootFile(filepath.Join(managedPrefix, nativeSmartUnit+".sha256"))
	if err != nil {
		return Fault("service_conflict", "native service digest untrusted")
	}
	sum := sha256.Sum256(unit)
	if strings.TrimSpace(string(digest)) != hex.EncodeToString(sum[:]) {
		return Fault("service_conflict", "native service differs from installer")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", nativeSmartUnit,
		"-p", "LoadState", "-p", "FragmentPath", "-p", "DropInPaths", "-p", "Transient")
	if err != nil {
		return err
	}
	out, err := cmd.Output()
	if err != nil {
		return Fault("service_state_unavailable", "native service identity unavailable")
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		pair := strings.SplitN(line, "=", 2)
		if len(pair) == 2 {
			fields[pair[0]] = pair[1]
		}
	}
	if fields["LoadState"] != "loaded" || fields["FragmentPath"] != nativeUnitPath ||
		fields["DropInPaths"] != "" || fields["Transient"] != "no" {
		return Fault("service_conflict", "native service unit provenance conflict")
	}
	return nil
}
func (m *Manager) nativeControl(args ...string) error {
	if err := m.nativeUnitOwnership(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, append(args, nativeSmartUnit)...)
	if err != nil {
		return err
	}
	if err := cmd.Run(); err != nil {
		return Fault("service_state_unavailable", "native systemd transition failed")
	}
	return nil
}
func (m *Manager) nativeActivity() (string, error) {
	if err := m.nativeUnitOwnership(); err != nil {
		return "unknown", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "is-active", nativeSmartUnit)
	if err != nil {
		return "unknown", err
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "unknown", Fault("service_state_unavailable", "native unit state timed out")
	}
	return parseUnitActivity(out, err)
}
func (m *Manager) nativeMainPIDZero() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd, err := trustedSystemctlCommand(ctx, "show", nativeSmartUnit, "-p", "MainPID", "--value")
	if err != nil {
		return err
	}
	raw, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(raw)) != "0" {
		return Fault("guard_pending", "native Core is not verified stopped")
	}
	return nil
}

// This is an inspection, not a resource reservation. systemd ExecStartPre
// repeats it immediately before native Core execution after receipt staging.
func inspectNativeAdmission(ctx context.Context, r nativeKernelRunner, p nativeRedirectRecovery) error {
	for _, family := range []string{"-4", "-6"} {
		rules, err := r.output(ctx, "ip", family, "rule", "show")
		if err != nil {
			return err
		}
		for _, line := range strings.Split(rules, "\n") {
			m := nativeRuleLine.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			priority, _ := strconv.Atoi(m[1])
			if priority == 1 || (priority >= p.Rule && priority <= p.Rule+10) ||
				strings.Contains(m[2], fmt.Sprintf("lookup %d", p.Table)) {
				return Fault("service_conflict", "native RPDB slots are occupied")
			}
		}
		routes, err := r.output(ctx, "ip", family, "route", "show", "table", strconv.Itoa(p.Table))
		if err != nil {
			return err
		}
		if strings.TrimSpace(routes) != "" {
			return Fault("service_conflict", "native policy table is occupied")
		}
	}
	tables, err := r.output(ctx, "nft", "list", "tables")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(tables, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "table" && f[2] == "sing-box" {
			return Fault("service_conflict", "sing-box nft table is already occupied")
		}
	}
	links, err := r.output(ctx, "ip", "-o", "link", "show")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(links, "\n") {
		pair := strings.SplitN(strings.TrimSpace(line), ": ", 3)
		if len(pair) > 1 && strings.SplitN(pair[1], "@", 2)[0] == p.TunnelIF {
			return Fault("service_conflict", "native TUN interface exists")
		}
	}
	underlay, err := r.output(ctx, "ip", "-o", "link", "show", "dev", p.UnderlayIF)
	if err != nil || strings.TrimSpace(underlay) == "" {
		return Fault("service_state_unavailable", "underlay interface not available")
	}
	return nil
}
func (s NativeSession) recoveryScope() nativeRedirectRecovery {
	return nativeRedirectRecovery{TunnelIF: s.InterfaceName, UnderlayIF: s.UnderlayIF,
		Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
}

// Never restart a retained crash-recovery receipt as a new user connection.
// Manual systemctl start and boot-time enabled units must obey the exact
// Manager-selected mode and profile, not just the presence of old config.
func nativeDesiredMatchesClaim(state State, session NativeSession) error {
	if state.Desired != "smart" || state.Selected != session.Selected {
		return Fault("guard_pending", "native Smart Routing is not the saved desired mode and profile")
	}
	return nil
}
func (m *Manager) NativePreflightInstalled() error {
	if err := m.nativeUnitOwnership(); err != nil {
		return err
	}
	return m.withLock(func() error {
		session, err := m.readNativeSession()
		if err != nil {
			return err
		}
		if err := m.validateNativeSessionConfig(session); err != nil {
			return err
		}
		state, err := m.load()
		if err != nil {
			return err
		}
		if err := nativeDesiredMatchesClaim(state, session); err != nil {
			return err
		}
		return inspectNativeAdmission(context.Background(), nativeSystemRunner{}, session.recoveryScope())
	})
}
func (m *Manager) NativeRecoverInstalled() error {
	if err := m.nativeUnitOwnership(); err != nil {
		return err
	}
	return m.withLock(func() error {
		session, err := m.readNativeSession()
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := m.validateNativeSessionConfig(session); err != nil {
			return err
		}
		if err := m.nativeMainPIDZero(); err != nil {
			return err
		}
		if err := recoverNativeRedirect(context.Background(), nativeSystemRunner{}, session.recoveryScope()); err != nil {
			return err
		}
		// Only after the exact owned network resources are independently
		// verified absent may the shutdown/crash hook finish the session.
		// This also avoids an enabled-on-reboot unit inheriting a contradictory
		// Direct desired state plus a stale recovery receipt.
		return m.finalizeNativeRecoveryLocked()
	})
}

// Called under the native lifecycle lock only AFTER recoverNativeRedirect has
// proved the exact owned RPDB, route and nftables objects are absent. Save
// Direct before retiring the one-use receipt: a crash between these writes
// leaves either a retryable receipt or a verified Direct session, never an
// unproven Smart session with no recovery identity.
func (m *Manager) finalizeNativeRecoveryLocked() error {
	state, err := m.load()
	if err != nil {
		return err
	}
	if state.Desired != "smart" && state.Desired != "direct" {
		return Fault("guard_pending", "native cleanup cannot finalize an unrelated desired mode")
	}
	if state.Desired == "smart" {
		state.Desired = "direct"
		if err := m.save(state); err != nil {
			return err
		}
	}
	// The receipt is the only authority to delete native kernel resources.
	// Remove it only after proven cleanup and a durable Direct state. A
	// leftover private config is inert and may be removed by exact Disconnect.
	if err := os.Remove(filepath.Join(m.Dir, nativeSessionFile)); err != nil {
		return err
	}
	dir, err := os.Open(m.Dir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	_ = dir.Close()
	return err
}

func (m *Manager) ConnectNativeSmartRouting(opts NativePolicyOptions) (NativeConnectionStatus, error) {
	result := NativeConnectionStatus{Desired: "smart", Observed: "not_started",
		CoreUnit: nativeSmartUnit, SelectedVPNPathProof: "not_run"}
	if err := m.nativeUnitOwnership(); err != nil {
		return result, err
	}
	if err := m.verifyUnitOwnership(); err != nil {
		return result, err
	}
	if err := EnsureCore(m.Core); err != nil {
		return result, err
	}
	// The private journal and Manager share the SAME .lock inode.
	// Acquire it once; never nest withLock and withActivationJournalLock.
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if phase, err := m.pendingSmartTUNTrial(); err != nil {
			return err
		} else if phase != "" {
			return Fault("guard_pending", "old TUN trial must be reconciled before native Smart Routing")
		}
		if _, err := m.readNativeSession(); err == nil {
			return Fault("guard_pending", "existing native session requires Disconnect")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		state, err := m.load()
		if err != nil {
			return err
		}
		if state.Desired != "direct" || state.Selected == "" {
			return Fault("invalid_state", "select a profile and disconnect other modes first")
		}
		observed, err := m.unitActive()
		if err != nil || observed == "active" {
			return Fault("service_conflict", "Proxy Only activity cannot be excluded")
		}
		observed, err = m.nativeActivity()
		if err != nil || observed == "active" {
			return Fault("service_conflict", "native Core activity cannot be excluded")
		}
		profile, err := m.profile(state.Selected)
		if err != nil {
			return err
		}
		document, _, _, err := loadSmartRoutingRulesLocked(store)
		if err != nil {
			return err
		}
		rules := append([]SmartRoutingRule(nil), document.Manual...)
		for _, source := range document.Imports {
			rules = append(rules, source.Rules...)
		}
		config, err := NativeSmartRoutingConfig(profile, opts, rules)
		if err != nil {
			return err
		}
		if err := CheckConfig(m.Core, m.Dir, config); err != nil {
			return err
		}
		scope := nativeRedirectRecovery{TunnelIF: opts.InterfaceName, UnderlayIF: opts.UnderlayInterface,
			Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}
		if err := inspectNativeAdmission(context.Background(), nativeSystemRunner{}, scope); err != nil {
			return err
		}
		sum := sha256.Sum256(config)
		session := NativeSession{Version: 1, Selected: state.Selected, InterfaceName: opts.InterfaceName,
			UnderlayIF: opts.UnderlayInterface, ConfigSHA256: hex.EncodeToString(sum[:])}
		claim, err := json.Marshal(session)
		if err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeConfigFile), config); err != nil {
			return err
		}
		if err := put(filepath.Join(m.Dir, nativeSessionFile), claim); err != nil {
			return err
		}
		state.Desired = "smart"
		if err := m.save(state); err != nil {
			return err
		}
		result.Selected = state.Selected
		result.RecoveryClaimPresent = true
		return nil
	})
	if err != nil {
		return result, err
	}
	// Keep the host's native unit disabled: boot must never reapply an
	// unconfirmed host-wide tunnel just because the last CLI connect used it.
	// Also correct a previously enabled but safely idle candidate unit.
	// The separate systemd stop hook still owns crash/shutdown cleanup.
	if err := m.nativeControl("disable"); err != nil {
		if cleanup := m.DisconnectNativeSmartRouting(); cleanup != nil {
			return result, Fault("guard_pending", "native activation disable failed and recovery remains uncertain")
		}
		return result, Fault("service_state_unavailable", "native unit could not be disabled; Direct restored")
	}
	// Never hold Manager lock while systemd's independent stop hook may need it.
	if err := m.nativeControl("start"); err != nil {
		if cleanup := m.DisconnectNativeSmartRouting(); cleanup != nil {
			return result, Fault("guard_pending", "native activation failed and recovery remains uncertain")
		}
		return result, Fault("service_state_unavailable", "native Core failed to start; Direct restored")
	}
	for i := 0; i < 25; i++ {
		observed, err := m.nativeActivity()
		if err == nil && observed == "active" {
			result.Observed = "active"
			// Active process is not a selected-path or policy-delivery proof.
			return result, nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	if cleanup := m.DisconnectNativeSmartRouting(); cleanup != nil {
		return result, Fault("guard_pending", "native Core never stabilized and recovery is uncertain")
	}
	return result, Fault("service_state_unavailable", "native Core did not stabilize; Direct restored")
}
func (m *Manager) DisconnectNativeSmartRouting() error {
	if err := m.nativeUnitOwnership(); err != nil {
		return err
	}
	// A matching active service can always be stopped independently of stale
	// local state. ExecStopPost owns kernel cleanup, not the stopped Core.
	if err := m.nativeControl("stop"); err != nil {
		return err
	}
	if err := m.nativeControl("disable"); err != nil {
		return err
	}
	if err := m.NativeRecoverInstalled(); err != nil {
		return err
	}
	// SIGKILL leaves systemd's owned service in failed state even after the
	// independent kernel cleanup has proved Direct/off. Normalize ONLY this
	// verified, stopped unit now, not at installer time or before recovery.
	activity, err := m.nativeActivity()
	if err != nil {
		return err
	}
	if activity == "failed" {
		if err := m.nativeControl("reset-failed"); err != nil {
			// A concurrent systemd GC may have already normalized the unit.
			// Read again rather than treating a failed command as success.
			if observed, observationErr := m.nativeActivity(); observationErr != nil || observed != "inactive" {
				return Fault("guard_pending", "native Core recovered but failed service state remains")
			}
		}
		activity, err = m.nativeActivity()
		if err != nil {
			return err
		}
	}
	if activity != "inactive" {
		return Fault("guard_pending", "native Core is not verified inactive after recovery")
	}
	return m.withLock(func() error {
		session, err := m.readNativeSession()
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if errors.Is(err, os.ErrNotExist) {
			state, stateErr := m.load()
			if stateErr != nil {
				return stateErr
			}
			if state.Desired != "direct" {
				return Fault("invalid_state", "native recovery claim missing; cannot verify Direct")
			}
			// The systemd stop hook may already have retired the receipt
			// after proving Direct. Remove only our inert private config;
			// no kernel cleanup is authorized by a missing receipt.
			config := filepath.Join(m.Dir, nativeConfigFile)
			if _, configErr := readRegular(config); configErr == nil {
				if err := os.Remove(config); err != nil {
					return err
				}
			} else if !errors.Is(configErr, os.ErrNotExist) {
				return configErr
			}
		}
		if err == nil {
			if err := m.validateNativeSessionConfig(session); err != nil {
				return err
			}
			for _, name := range []string{nativeSessionFile, nativeConfigFile} {
				if e := os.Remove(filepath.Join(m.Dir, name)); e != nil {
					return e
				}
			}
			dir, e := os.Open(m.Dir)
			if e != nil {
				return e
			}
			e = dir.Sync()
			_ = dir.Close()
			if e != nil {
				return e
			}
		}
		s, err := m.load()
		if err != nil {
			return err
		}
		s.Desired = "direct"
		return m.save(s)
	})
}
func (m *Manager) NativeStatus() (NativeConnectionStatus, error) {
	result := NativeConnectionStatus{CoreUnit: nativeSmartUnit, SelectedVPNPathProof: "not_run"}
	err := m.withLock(func() error {
		s, err := m.load()
		if err != nil {
			return err
		}
		result.Desired = s.Desired
		result.Selected = s.Selected
		session, err := m.readNativeSession()
		if errors.Is(err, os.ErrNotExist) {
			if s.Desired == "smart" {
				return Fault("invalid_state", "Smart Routing desired but native recovery claim missing")
			}
			// A Core crash can leave the exact service failed even though its
			// independent stop hook already restored Direct. Do not claim
			// inactive solely because its recovery receipt was removed.
			observed, stateErr := m.nativeActivity()
			if stateErr != nil {
				return stateErr
			}
			result.Observed = observed
			if observed == "active" {
				return Fault("guard_pending", "native Core unexpectedly active without recovery claim")
			}
			return nil
		}
		if err != nil {
			return err
		}
		result.RecoveryClaimPresent = true
		if err := m.validateNativeSessionConfig(session); err != nil {
			return err
		}
		observed, err := m.nativeActivity()
		if err != nil {
			return err
		}
		result.Observed = observed
		if s.Desired != "smart" || observed != "active" {
			return Fault("guard_pending", "native Core is not verified active and consistent")
		}
		return nil
	})
	return result, err
}
