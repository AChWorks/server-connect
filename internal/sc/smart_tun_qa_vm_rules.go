package sc

import (
	"encoding/json"
	"net/netip"
)

// This legacy VM lane reads the same saved operator-rule registry used
// by the active native policy. The selection and admission snapshot
// are covered by the existing exclusive activation-journal lock. No new
// untrusted domain-to-Direct translation is introduced.
func smartTUNVMApplySavedRules(base SmartTUNCandidateOptions, doc smartRoutingRulesDocument) (SmartTUNCandidateOptions, error) {
	base.Exceptions = nil
	base.IPv6Exceptions = nil
	base.DomainExceptions = nil
	for _, rule := range doc.Manual {
		if err := appendLegacyVMRule(&base, rule); err != nil {
			return base, err
		}
	}
	for _, source := range doc.Imports {
		for _, rule := range source.Rules {
			if err := appendLegacyVMRule(&base, rule); err != nil {
				return base, err
			}
		}
	}
	if !smartTUNVMPolicySupported(base) {
		return base, Fault("routing_rules_invalid", "the guarded non-Docker VM admits up to eight explicit IPv4 CIDR rules; VPN health witnesses must remain selected")
	}
	return base, nil
}

func smartTUNVMReadSavedRulesLocked(store *activationJournalDir, base SmartTUNCandidateOptions) (SmartTUNCandidateOptions, string, error) {
	doc, _, _, err := loadSmartRoutingRulesLocked(store)
	if err != nil {
		return base, "", err
	}
	result, err := smartTUNVMApplySavedRules(base, doc)
	if err != nil {
		return base, "", err
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return base, "", Fault("routing_rules_invalid", "cannot bind saved routing rules snapshot")
	}
	return result, sha256Hex(data), nil
}

// Saved-rule projection is retained only for legacy VM recovery/QA.
func appendLegacyVMRule(opts *SmartTUNCandidateOptions, r SmartRoutingRule) error {
	if _, err := normalizeSmartRoutingRule(r); err != nil {
		return err
	}
	switch r.Type {
	case "cidr":
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return routingRuleInvalid()
		}
		if p.Addr().Is4() {
			opts.Exceptions = append(opts.Exceptions, SmartTUNCIDRException{CIDR: r.Value, Via: r.Via})
		} else {
			opts.IPv6Exceptions = append(opts.IPv6Exceptions, SmartTUNCIDRException{CIDR: r.Value, Via: r.Via})
		}
	case "domain", "suffix":
		opts.DomainExceptions = append(opts.DomainExceptions, SmartTUNDomainException{
			Domain: r.Value, Suffix: r.Type == "suffix", Via: r.Via,
		})
	default:
		return routingRuleInvalid()
	}
	return nil
}
