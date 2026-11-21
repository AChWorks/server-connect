//go:build linux

package sc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The stop hook retires the one-use native kernel receipt after exact cleanup,
// but deliberately retains the credential-bearing Core plan. On reboot it is
// inert, yet its presence used to block the first Proxy Only connection.
// This path NEVER recovers kernel objects with a missing claim. It may retire
// only a digest-matched private plan after independently proving empty native
// resources and quiescent, correctly owned service and guard units.
func nativeOffConfigTunnel(raw []byte, health NativeHealthState) (string, error) {
	if health.Phase != "off" || !journalHex64.MatchString(health.ConfigSHA256) ||
		len(raw) == 0 || len(raw) > 4*1024*1024 || rejectAmbiguousJournalJSON(raw) != nil {
		return "", Fault("guard_pending", "native plan has no complete, verified Off receipt; use Disconnect for recovery")
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != health.ConfigSHA256 {
		return "", Fault("guard_pending", "native plan differs from retired Off receipt; inspect before Disconnect")
	}
	var cfg struct {
		Inbounds []struct {
			Type          string `json:"type"`
			InterfaceName string `json:"interface_name"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &cfg) != nil || len(cfg.Inbounds) != 1 ||
		cfg.Inbounds[0].Type != "tun" ||
		!nativeInterfaceName.MatchString(cfg.Inbounds[0].InterfaceName) ||
		cfg.Inbounds[0].InterfaceName == "lo" {
		return "", Fault("guard_pending", "retired native plan is invalid; inspect before Disconnect")
	}
	return cfg.Inbounds[0].InterfaceName, nil
}

// Kept injectable to prove verification occurs on both sides of removal.
// A post-delete observation failure is reported, never represented as a
// successful Direct/Proxy activation.
func reconcileRetiredNativePlan(verify func() error, remove func() error) error {
	if err := verify(); err != nil {
		return err
	}
	if err := remove(); err != nil {
		return err
	}
	return verify()
}

func (m *Manager) reconcileNativeOffConfigForProxy() error {
	return m.withLock(func() error {
		path := filepath.Join(m.Dir, nativeConfigFile)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
			!ownedByRoot(info) || info.Size() < 1 || info.Size() > 4*1024*1024 {
			return Fault("guard_pending", "retired native plan ownership uncertain; inspect and use Disconnect")
		}
		raw, err := readRegular(path)
		if err != nil {
			return Fault("guard_pending", "retired native plan unavailable; inspect and use Disconnect")
		}
		health, err := m.readNativeHealth()
		if err != nil {
			return Fault("guard_pending", "native Off health receipt missing or invalid; inspect and use Disconnect")
		}
		tunnel, err := nativeOffConfigTunnel(raw, health)
		if err != nil {
			return err
		}
		if err := m.nativeUnitOwnership(); err != nil {
			return err
		}
		verify := func() error {
			state, err := m.load()
			if err != nil || state.Desired != "direct" {
				return Fault("guard_pending", "native Off has not been committed; use Disconnect")
			}
			if _, err := m.readNativeSession(); !errors.Is(err, os.ErrNotExist) {
				return Fault("guard_pending", "native recovery claim still exists or is untrusted; use Disconnect")
			}
			if phase, err := m.pendingLegacyActivationJournal(); err != nil || phase != "" {
				return Fault("guard_pending", "another activation journal has not been retired")
			}
			current, err := m.readNativeHealth()
			if err != nil || current != health || current.Phase != "off" {
				return Fault("guard_pending", "native Off receipt changed during reconciliation")
			}
			if _, err := os.Lstat(filepath.Join(m.Dir, nativeStartupFile)); !errors.Is(err, os.ErrNotExist) {
				return Fault("guard_pending", "native startup receipt remains unresolved; use Disconnect")
			}
			activity, err := m.nativeActivity()
			if err != nil || (activity != "inactive" && activity != "failed") {
				return Fault("guard_pending", "native Core is not independently idle; use Disconnect")
			}
			if err := m.nativeCoreRecoveryQuiescent(); err != nil {
				return err
			}
			proxyActivity, err := m.unitActive()
			if err != nil || proxyActivity != "inactive" {
				return Fault("guard_pending", "Proxy Only service is not verified idle")
			}
			if err := trialGuardUnits(false); err != nil {
				return err
			}
			if _, err := nativeHealthUnits(false, nil); err != nil {
				return err
			}
			// No session survives to authorize cleanup, including of a
			// lookalike owned slot. Any occupied policy is a hard conflict.
			if err := inspectNativeAdmission(context.Background(), nativeSystemRunner{},
				nativeRedirectRecovery{TunnelIF: tunnel, Table: NativePolicyTableIndex, Rule: NativePolicyRuleIndex}); err != nil {
				return err
			}
			// Normal preflight intentionally allows its own already-installed
			// startup barrier. Off reconciliation cannot: a retired claim
			// provides no authority to adopt ANY leftover sc_pre_ table.
			tables, err := (nativeSystemRunner{}).output(context.Background(), "nft", "list", "tables")
			if err != nil {
				return err
			}
			return nativeOffStartupTablesEmpty(tables)
		}
		return reconcileRetiredNativePlan(verify, func() error {
			// Stay inside BOTH native transition and Manager locks. The old
			// plan is not kernel authority: only the private file is removed.
			if err := os.Remove(path); err != nil {
				return err
			}
			dir, err := os.Open(m.Dir)
			if err != nil {
				return err
			}
			err = dir.Sync()
			_ = dir.Close()
			return err
		})
	})
}

// Off mode cannot inherit a startup barrier from any (even an identical)
// former operation. Normal ExecStartPre is allowed to see its *own* barrier,
// but a missing recovery claim permits no kernel-object adoption.
func nativeOffStartupTablesEmpty(tables string) error {
	for _, line := range strings.Split(tables, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && strings.HasPrefix(fields[2], "sc_pre_") {
			return Fault("service_conflict", "native startup containment exists without an active claim")
		}
	}
	return nil
}
