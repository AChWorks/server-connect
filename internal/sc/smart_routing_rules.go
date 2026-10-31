package sc

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const smartRoutingRulesFilename = "smart-routing-rules.json"
const MaxSmartRoutingImportBytes = 64 << 10
const maxSmartRoutingCIDRs = 128
const maxSmartRoutingDomains = 128

var routingSourcePattern = regexp.MustCompile("^[a-z][a-z0-9_-]{0,63}$")
var routingSHA256Pattern = regexp.MustCompile("^[a-f0-9]{64}$")

// SmartRoutingRule is an operator-supplied *saved* routing exception, not
// permission to change a host policy. Domain Direct is deliberately rejected:
// client-controlled Host/SNI is not authenticated destination DNS correlation.
type SmartRoutingRule struct {
	Type  string `json:"type"` // cidr, domain, suffix
	Value string `json:"value"`
	Via   string `json:"via"` // direct or vpn; domains are vpn-only
}

type smartRoutingRuleSource struct {
	Source       string             `json:"source"`
	AsOf         string             `json:"as_of"`
	SourceSHA256 string             `json:"source_sha256"`
	Rules        []SmartRoutingRule `json:"rules"`
}
type smartRoutingRulesDocument struct {
	Version  int                      `json:"version"`
	Revision uint64                   `json:"revision"`
	Manual   []SmartRoutingRule       `json:"manual"`
	Imports  []smartRoutingRuleSource `json:"imports"`
}
type SmartRoutingRuleView struct {
	SmartRoutingRule
	Source string `json:"source"` // "manual" or the imported source name
}
type SmartRoutingRuleImportView struct {
	Source                     string `json:"source"`
	AsOf                       string `json:"as_of"`
	SourceSHA256               string `json:"source_sha256"`
	RuleCount                  int    `json:"rule_count"`
	AgeDays                    int    `json:"age_days"`
	StaleOver30Days            bool   `json:"stale_over_30_days"`
	PublisherSignatureVerified bool   `json:"publisher_signature_verified"`
}
type SmartRoutingRulesReport struct {
	Present             bool                         `json:"present"`
	Version             int                          `json:"version"`
	Revision            uint64                       `json:"revision"`
	State               string                       `json:"state"`
	ActivationReady     bool                         `json:"activation_ready"`
	GeneralHostAdmitted bool                         `json:"general_host_admitted"`
	Rules               []SmartRoutingRuleView       `json:"rules"`
	Imports             []SmartRoutingRuleImportView `json:"imports"`
}

func routingRuleInvalid() error {
	return Fault("routing_rules_invalid", "rule syntax, protected address or supported action is invalid")
}
func routingRuleConflict() error {
	return Fault("routing_rules_conflict", "routing rules overlap or conflict with current saved settings")
}

func normalizeSmartRoutingRule(x SmartRoutingRule) (SmartRoutingRule, error) {
	if x.Type != "cidr" && x.Type != "domain" && x.Type != "suffix" || (x.Via != "direct" && x.Via != "vpn") ||
		x.Value == "" || len(x.Value) > 253 {
		return SmartRoutingRule{}, routingRuleInvalid()
	}
	if x.Type == "cidr" {
		prefix, err := netip.ParsePrefix(x.Value)
		if err != nil || !prefix.IsValid() || prefix.Masked() != prefix || prefix.String() != x.Value ||
			!prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() ||
			prefix.Addr().IsLoopback() || prefix.Addr().IsLinkLocalUnicast() ||
			prefix.Addr().IsMulticast() || prefix.Addr().IsUnspecified() ||
			overlapsSpecialPurpose(prefix) {
			return SmartRoutingRule{}, routingRuleInvalid()
		}
		if prefix.Addr().Is4() {
			if (x.Via == "direct" && prefix.Bits() < 24) || (x.Via == "vpn" && prefix.Bits() < 8) {
				return SmartRoutingRule{}, routingRuleInvalid()
			}
		} else if (x.Via == "direct" && prefix.Bits() < 64) || (x.Via == "vpn" && prefix.Bits() < 32) {
			return SmartRoutingRule{}, routingRuleInvalid()
		}
	} else {
		if x.Via != "vpn" {
			return SmartRoutingRule{}, Fault("routing_rules_invalid", "Direct domain exceptions require trusted DNS/IP correlation and are not supported")
		}
		// A whole public suffix cannot be a narrow operator exception.
		if x.Type == "suffix" && !strings.Contains(x.Value, ".") {
			return SmartRoutingRule{}, routingRuleInvalid()
		}
		normalized, err := canonicalSmartTUNDomain(x.Value, x.Type == "suffix")
		if err != nil || normalized != x.Value {
			return SmartRoutingRule{}, routingRuleInvalid()
		}
	}
	return x, nil
}

func validateSmartRoutingAsOf(s string, now time.Time) (time.Time, error) {
	d, err := time.Parse("2006-01-02", s)
	if err != nil || d.Format("2006-01-02") != s || d.After(now.UTC().Truncate(24*time.Hour)) {
		return time.Time{}, Fault("routing_rules_invalid", "source date is invalid or in the future")
	}
	return d, nil
}
func validateSmartRoutingDocument(v smartRoutingRulesDocument, now time.Time) error {
	if v.Version != 1 || v.Revision == 0 || len(v.Manual) > maxSmartRoutingCIDRs+maxSmartRoutingDomains || len(v.Imports) > 16 {
		return routingRuleInvalid()
	}
	var cidrs []netip.Prefix
	// Mirror native compiler aggregate Direct limits at persistence time.
	directV4Blocks := map[netip.Prefix]bool{}
	directV6Blocks := map[netip.Prefix]bool{}
	seen := map[string]bool{}
	sources := map[string]bool{}
	cidrN, domainN := 0, 0
	scan := func(x SmartRoutingRule) error {
		y, err := normalizeSmartRoutingRule(x)
		if err != nil || y != x {
			return routingRuleInvalid()
		}
		key := x.Type + ":" + x.Value
		if seen[key] {
			return routingRuleConflict()
		}
		seen[key] = true
		if x.Type == "cidr" {
			cidrN++
			p, _ := netip.ParsePrefix(x.Value)
			for _, other := range cidrs {
				if routePrefixesOverlap(p, other) {
					return routingRuleConflict()
				}
			}
			cidrs = append(cidrs, p)
			if x.Via == "direct" {
				if p.Addr().Is4() {
					directV4Blocks[netip.PrefixFrom(p.Addr(), 24).Masked()] = true
					if len(directV4Blocks) > 64 {
						return routingRuleInvalid()
					}
				} else {
					directV6Blocks[netip.PrefixFrom(p.Addr(), 64).Masked()] = true
					if len(directV6Blocks) > 64 {
						return routingRuleInvalid()
					}
				}
			}
		} else {
			domainN++
		}
		if cidrN > maxSmartRoutingCIDRs || domainN > maxSmartRoutingDomains {
			return routingRuleInvalid()
		}
		return nil
	}
	for _, x := range v.Manual {
		if err := scan(x); err != nil {
			return err
		}
	}
	for _, imp := range v.Imports {
		if !routingSourcePattern.MatchString(imp.Source) || imp.Source == "manual" || sources[imp.Source] ||
			!routingSHA256Pattern.MatchString(imp.SourceSHA256) || len(imp.Rules) == 0 {
			return routingRuleInvalid()
		}
		if _, err := validateSmartRoutingAsOf(imp.AsOf, now); err != nil {
			return err
		}
		sources[imp.Source] = true
		for _, x := range imp.Rules {
			if err := scan(x); err != nil {
				return err
			}
		}
	}
	return nil
}
func strictSmartRoutingRulesJSON(data []byte) (smartRoutingRulesDocument, error) {
	invalid := func() (smartRoutingRulesDocument, error) {
		return smartRoutingRulesDocument{}, Fault("routing_rules_invalid", "saved routing rules schema is malformed, stale or untrusted")
	}
	if len(data) == 0 || len(data) > activationJournalMaxBytes || rejectAmbiguousJournalJSON(data) != nil ||
		requireExactJournalKeys(data, map[string]bool{"version": true, "revision": true, "manual": true, "imports": true}) != nil {
		return invalid()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != 4 {
		return invalid()
	}
	var manual, imports []json.RawMessage
	if bytes.Equal(bytes.TrimSpace(fields["manual"]), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(fields["imports"]), []byte("null")) {
		return invalid()
	}
	if json.Unmarshal(fields["manual"], &manual) != nil || json.Unmarshal(fields["imports"], &imports) != nil ||
		len(manual) > 256 || len(imports) > 16 {
		return invalid()
	}
	for _, raw := range manual {
		if requireExactJournalKeys(raw, map[string]bool{"type": true, "value": true, "via": true}) != nil {
			return invalid()
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || len(m) != 3 {
			return invalid()
		}
	}
	for _, raw := range imports {
		if requireExactJournalKeys(raw, map[string]bool{"source": true, "as_of": true, "source_sha256": true, "rules": true}) != nil {
			return invalid()
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil || len(m) != 4 {
			return invalid()
		}
		var rules []json.RawMessage
		if bytes.Equal(bytes.TrimSpace(m["rules"]), []byte("null")) ||
			json.Unmarshal(m["rules"], &rules) != nil || len(rules) > 256 {
			return invalid()
		}
		for _, entry := range rules {
			if requireExactJournalKeys(entry, map[string]bool{"type": true, "value": true, "via": true}) != nil {
				return invalid()
			}
			var cols map[string]json.RawMessage
			if json.Unmarshal(entry, &cols) != nil || len(cols) != 3 {
				return invalid()
			}
		}
	}
	var value smartRoutingRulesDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&value) != nil {
		return invalid()
	}
	var extra any
	if !errors.Is(dec.Decode(&extra), io.EOF) {
		return invalid()
	}
	if validateSmartRoutingDocument(value, time.Now()) != nil {
		return invalid()
	}
	return value, nil
}
func emptySmartRoutingDocument() smartRoutingRulesDocument {
	return smartRoutingRulesDocument{Version: 1, Manual: []SmartRoutingRule{}, Imports: []smartRoutingRuleSource{}}
}
func loadSmartRoutingRulesLocked(store *activationJournalDir) (smartRoutingRulesDocument, *activationJournalFileIdentity, bool, error) {
	raw, id, err := store.readSmartTUNFile(smartRoutingRulesFilename)
	if errors.Is(err, os.ErrNotExist) {
		return emptySmartRoutingDocument(), nil, false, nil
	}
	if err != nil {
		return smartRoutingRulesDocument{}, nil, false, err
	}
	value, err := strictSmartRoutingRulesJSON(raw)
	if err != nil {
		return smartRoutingRulesDocument{}, nil, false, err
	}
	return value, &id, true, nil
}
func smartRoutingRulesReport(v smartRoutingRulesDocument, present bool, now time.Time) SmartRoutingRulesReport {
	out := SmartRoutingRulesReport{Present: present, Version: 1, Revision: v.Revision, State: "saved_not_applied",
		ActivationReady: false, GeneralHostAdmitted: false,
		Rules: []SmartRoutingRuleView{}, Imports: []SmartRoutingRuleImportView{}}
	for _, r := range v.Manual {
		out.Rules = append(out.Rules, SmartRoutingRuleView{SmartRoutingRule: r, Source: "manual"})
	}
	for _, imp := range v.Imports {
		date, _ := validateSmartRoutingAsOf(imp.AsOf, now)
		age := int(now.UTC().Truncate(24*time.Hour).Sub(date).Hours() / 24)
		out.Imports = append(out.Imports, SmartRoutingRuleImportView{Source: imp.Source, AsOf: imp.AsOf, SourceSHA256: imp.SourceSHA256,
			RuleCount: len(imp.Rules), AgeDays: age, StaleOver30Days: age > 30, PublisherSignatureVerified: false})
		for _, r := range imp.Rules {
			out.Rules = append(out.Rules, SmartRoutingRuleView{SmartRoutingRule: r, Source: imp.Source})
		}
	}
	return out
}
func (m *Manager) InspectSmartRoutingRules() (SmartRoutingRulesReport, error) {
	var report SmartRoutingRulesReport
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		v, _, present, err := loadSmartRoutingRulesLocked(store)
		if err != nil {
			return err
		}
		report = smartRoutingRulesReport(v, present, time.Now())
		return nil
	})
	return report, err
}
func smartRoutingRulesInactiveLocked(store *activationJournalDir) error {
	_, _, err := store.readJournal()
	if err == nil {
		return Fault("guard_pending", "reconcile the existing activation journal before changing saved routing rules")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Fault("guard_pending", "activation journal is unavailable or untrusted; no rule modification allowed")
	}
	return nil
}
func (m *Manager) changeSmartRoutingRules(edit func(*smartRoutingRulesDocument) (bool, error)) (SmartRoutingRulesReport, error) {
	var out SmartRoutingRulesReport
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		if err := smartRoutingRulesInactiveLocked(store); err != nil {
			return err
		}
		v, id, present, err := loadSmartRoutingRulesLocked(store)
		if err != nil {
			return err
		}
		changed, err := edit(&v)
		if err != nil {
			return err
		}
		if changed {
			v.Revision++
			if err := validateSmartRoutingDocument(v, time.Now()); err != nil {
				return err
			}
			encoded, err := json.Marshal(v)
			if err != nil {
				return Fault("routing_rules_invalid", "cannot encode saved routing rules")
			}
			encoded = append(encoded, '\n')
			if err := store.writeSmartTUNFile(smartRoutingRulesFilename, encoded, id); err != nil {
				return err
			}
			present = true
		}
		out = smartRoutingRulesReport(v, present, time.Now())
		return nil
	})
	return out, err
}
func sortSmartRoutingRules(items []SmartRoutingRule) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Type != items[j].Type {
			return items[i].Type < items[j].Type
		}
		return items[i].Value < items[j].Value
	})
}
func (m *Manager) AddSmartRoutingRule(v SmartRoutingRule) (SmartRoutingRulesReport, error) {
	normalized, err := normalizeSmartRoutingRule(v)
	if err != nil {
		return SmartRoutingRulesReport{}, err
	}
	return m.changeSmartRoutingRules(func(doc *smartRoutingRulesDocument) (bool, error) {
		doc.Manual = append(doc.Manual, normalized)
		sortSmartRoutingRules(doc.Manual)
		return true, nil
	})
}
func (m *Manager) RemoveSmartRoutingRule(kind, value string) (SmartRoutingRulesReport, error) {
	if _, err := normalizeSmartRoutingRule(SmartRoutingRule{Type: kind, Value: value, Via: "vpn"}); err != nil {
		return SmartRoutingRulesReport{}, err
	}
	return m.changeSmartRoutingRules(func(doc *smartRoutingRulesDocument) (bool, error) {
		for i, r := range doc.Manual {
			if r.Type == kind && r.Value == value {
				doc.Manual = append(doc.Manual[:i], doc.Manual[i+1:]...)
				return true, nil
			}
		}
		return false, Fault("routing_rules_missing", "the requested manual rule is absent (imported entries are source-owned)")
	})
}
func (m *Manager) RemoveSmartRoutingSource(source, expectedSHA string) (SmartRoutingRulesReport, error) {
	if !routingSourcePattern.MatchString(source) || !routingSHA256Pattern.MatchString(expectedSHA) {
		return SmartRoutingRulesReport{}, routingRuleInvalid()
	}
	return m.changeSmartRoutingRules(func(doc *smartRoutingRulesDocument) (bool, error) {
		for i, r := range doc.Imports {
			if r.Source == source {
				if r.SourceSHA256 != expectedSHA {
					return false, routingRuleConflict()
				}
				doc.Imports = append(doc.Imports[:i], doc.Imports[i+1:]...)
				return true, nil
			}
		}
		return false, Fault("routing_rules_missing", "the imported source does not exist")
	})
}
func parseSmartRoutingImport(raw []byte) ([]SmartRoutingRule, error) {
	if len(raw) == 0 || len(raw) > MaxSmartRoutingImportBytes {
		return nil, routingRuleInvalid()
	}
	for _, ch := range raw {
		if ch > 126 || (ch < 32 && ch != '\n') {
			return nil, routingRuleInvalid()
		}
	}
	rows := strings.Split(string(raw), "\n")
	if len(rows) > 512 {
		return nil, routingRuleInvalid()
	}
	rules := make([]SmartRoutingRule, 0, 16)
	for _, line := range rows {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		words := strings.Fields(line)
		if len(words) != 3 {
			return nil, routingRuleInvalid()
		}
		value, err := normalizeSmartRoutingRule(SmartRoutingRule{Type: words[0], Via: words[1], Value: words[2]})
		if err != nil {
			return nil, err
		}
		rules = append(rules, value)
		if len(rules) > maxSmartRoutingCIDRs+maxSmartRoutingDomains {
			return nil, routingRuleInvalid()
		}
	}
	if len(rules) == 0 {
		return nil, routingRuleInvalid()
	}
	sortSmartRoutingRules(rules)
	return rules, nil
}
func (m *Manager) ImportSmartRoutingRules(source, asOf, expectedSHA, replaceSHA string, raw []byte) (SmartRoutingRulesReport, error) {
	if !routingSourcePattern.MatchString(source) || source == "manual" ||
		!routingSHA256Pattern.MatchString(expectedSHA) || (replaceSHA != "" && !routingSHA256Pattern.MatchString(replaceSHA)) {
		return SmartRoutingRulesReport{}, routingRuleInvalid()
	}
	if _, err := validateSmartRoutingAsOf(asOf, time.Now()); err != nil {
		return SmartRoutingRulesReport{}, err
	}
	digest := sha256.Sum256(raw)
	expected, err := hex.DecodeString(expectedSHA)
	if err != nil || subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return SmartRoutingRulesReport{}, Fault("routing_rules_hash_mismatch", "the local imported rule list does not match its independently supplied SHA-256")
	}
	rules, err := parseSmartRoutingImport(raw)
	if err != nil {
		return SmartRoutingRulesReport{}, err
	}
	return m.changeSmartRoutingRules(func(doc *smartRoutingRulesDocument) (bool, error) {
		for i, imp := range doc.Imports {
			if imp.Source == source {
				if imp.SourceSHA256 == expectedSHA && imp.AsOf == asOf {
					if len(imp.Rules) == len(rules) {
						identical := true
						for j := range rules {
							if rules[j] != imp.Rules[j] {
								identical = false
								break
							}
						}
						if identical {
							return false, nil
						}
					}
				}
				if replaceSHA == "" || imp.SourceSHA256 != replaceSHA {
					return false, routingRuleConflict()
				}
				doc.Imports[i] = smartRoutingRuleSource{Source: source, AsOf: asOf, SourceSHA256: expectedSHA, Rules: rules}
				return true, nil
			}
		}
		if replaceSHA != "" {
			return false, Fault("routing_rules_missing", "the expected source for replacement does not exist")
		}
		doc.Imports = append(doc.Imports, smartRoutingRuleSource{Source: source, AsOf: asOf, SourceSHA256: expectedSHA, Rules: rules})
		sort.Slice(doc.Imports, func(i, j int) bool { return doc.Imports[i].Source < doc.Imports[j].Source })
		return true, nil
	})
}

// SmartRoutingRulesPreview checks the exact native sing-box candidate compiler
// using the currently selected profile and saved settings. It never persists
// an active operation, arms a guard or modifies any kernel path.
type SmartRoutingRulesPreview struct {
	RulesRevision        uint64 `json:"rules_revision"`
	SelectedProfileID    string `json:"selected_profile_id"`
	RuleCount            int    `json:"rule_count"`
	NativeConfigSHA256   string `json:"native_config_sha256"`
	ValidationLevel      string `json:"validation_level"`
	CoreExecutionTested  bool   `json:"core_execution_tested"`
	HostNetworkInspected bool   `json:"host_network_inspected"`
	ActivationReady      bool   `json:"activation_ready"`
	Applied              bool   `json:"applied"`
}

func (m *Manager) PreviewSmartRoutingRules(opts SmartTUNCandidateOptions) (SmartRoutingRulesPreview, error) {
	var out SmartRoutingRulesPreview
	if len(opts.Exceptions) != 0 || len(opts.DomainExceptions) != 0 || len(opts.IPv6Exceptions) != 0 {
		return out, Fault("invalid_arguments", "preview policy exceptions must come only from saved, validated routing rules")
	}
	err := m.withActivationJournalLock(syscall.Fsync, func(store *activationJournalDir) error {
		doc, _, _, err := loadSmartRoutingRulesLocked(store)
		if err != nil {
			return err
		}
		state, err := m.load()
		if err != nil || state.Selected == "" {
			return Fault("invalid_profile", "select a verified saved profile before previewing Smart Routing policy")
		}
		profile, err := m.profile(state.Selected)
		if err != nil {
			return Fault("invalid_profile", "selected private profile is absent or invalid")
		}
		for _, r := range doc.Manual {
			if err := appendRoutingPreviewRule(&opts, r); err != nil {
				return err
			}
		}
		for _, source := range doc.Imports {
			for _, r := range source.Rules {
				if err := appendRoutingPreviewRule(&opts, r); err != nil {
					return err
				}
			}
		}
		cfg, err := smartTUNNativeConfig(profile, opts)
		if err != nil {
			return Fault("routing_rules_invalid", "native compiler rejected the selected profile, underlay or routing exceptions")
		}
		digest := sha256.Sum256(cfg)
		out = SmartRoutingRulesPreview{RulesRevision: doc.Revision, SelectedProfileID: state.Selected,
			RuleCount: len(doc.Manual), NativeConfigSHA256: hex.EncodeToString(digest[:]),
			ValidationLevel: "native_policy_compile_only", CoreExecutionTested: false,
			HostNetworkInspected: false, ActivationReady: false, Applied: false}
		for _, v := range doc.Imports {
			out.RuleCount += len(v.Rules)
		}
		return nil
	})
	return out, err
}
func appendRoutingPreviewRule(opts *SmartTUNCandidateOptions, r SmartRoutingRule) error {
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
