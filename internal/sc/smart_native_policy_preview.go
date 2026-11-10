package sc

import (
	"crypto/sha256"
	"encoding/hex"
	"syscall"
)

// NativePolicyPreview proves only that the currently saved policy compiles
// against the exact installed official Core. It never touches system routing.
type NativePolicyPreview struct {
	SelectedProfileID    string `json:"selected_profile_id"`
	RulesRevision        uint64 `json:"rules_revision"`
	RuleCount            int    `json:"rule_count"`
	Mode                 string `json:"mode"`
	NativeConfigSHA256   string `json:"native_config_sha256"`
	CoreVersion          string `json:"core_version"`
	ValidationLevel      string `json:"validation_level"`
	CoreConfigAccepted   bool   `json:"core_config_accepted"`
	HostNetworkInspected bool   `json:"host_network_inspected"`
	Applied              bool   `json:"applied"`
	ActivationReady      bool   `json:"activation_ready"`
	GeneralHostAdmitted  bool   `json:"general_host_admitted"`
}

func (m *Manager) PreviewNativeSmartRouting(opts NativePolicyOptions) (NativePolicyPreview, error) {
	var out NativePolicyPreview
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		doc, _, _, err := loadSmartRoutingRulesLocked(store)
		if err != nil {
			return err
		}
		s, err := m.load()
		if err != nil || s.Selected == "" {
			return Fault("invalid_profile", "select a saved profile before native policy preview")
		}
		profile, err := m.profile(s.Selected)
		if err != nil {
			return Fault("invalid_profile", "the selected saved profile cannot be read")
		}
		rules := append([]SmartRoutingRule(nil), doc.Manual...)
		for _, source := range doc.Imports {
			rules = append(rules, source.Rules...)
		}
		config, err := NativeSmartRoutingConfig(profile, opts, rules)
		if err != nil {
			return Fault("routing_rules_invalid", "saved rules or native Core policy are invalid")
		}
		if err := EnsureCore(m.Core); err != nil {
			return err
		}
		if err := CheckConfig(m.Core, m.Dir, config); err != nil {
			return err
		}
		sum := sha256.Sum256(config)
		out = NativePolicyPreview{
			SelectedProfileID:    s.Selected,
			RulesRevision:        doc.Revision,
			RuleCount:            len(rules),
			Mode:                 opts.Mode,
			NativeConfigSHA256:   hex.EncodeToString(sum[:]),
			CoreVersion:          CoreVersion,
			ValidationLevel:      "pinned_official_core_check_only",
			CoreConfigAccepted:   true,
			HostNetworkInspected: false,
			Applied:              false,
			ActivationReady:      false,
			GeneralHostAdmitted:  false,
		}
		return nil
	})
	return out, err
}
