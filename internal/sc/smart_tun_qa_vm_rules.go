package sc

import (
	"encoding/json"
)

// This fixed VM lane reads the same saved operator-rule registry used by
// smart-routing-rules and its preview. The selection and admission snapshot
// are covered by the existing exclusive activation-journal lock. No new
// untrusted domain-to-Direct translation is introduced.
func smartTUNVMApplySavedRules(base SmartTUNCandidateOptions, doc smartRoutingRulesDocument) (SmartTUNCandidateOptions, error) {
	base.Exceptions = nil
	base.IPv6Exceptions = nil
	base.DomainExceptions = nil
	for _, rule := range doc.Manual {
		if err := appendRoutingPreviewRule(&base, rule); err != nil {
			return base, err
		}
	}
	for _, source := range doc.Imports {
		for _, rule := range source.Rules {
			if err := appendRoutingPreviewRule(&base, rule); err != nil {
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
