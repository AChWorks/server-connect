// Server Connect manages explicit proxy use and precisely owned experimental TUN policy.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/AChWorks/server-connect/internal/sc"
)

const managerVersion = "0.1.0-dev"

type envelope struct {
	OK    bool      `json:"ok"`
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

// destinationFlags supports repeated explicit --destination CIDR arguments.
type destinationFlags []string

func (d *destinationFlags) String() string { return strings.Join(*d, ",") }
func (d *destinationFlags) Set(value string) error {
	*d = append(*d, value)
	return nil
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func output(j bool, value any, err error) int {
	if j {
		out := envelope{OK: err == nil, Data: value}
		if err != nil {
			// Preserve safe partial diagnostic data (HTTP status/path/timing),
			// while the failure remains explicit in ok=false and exit code.
			out.Error = &apiError{Code: sc.ErrorCode(err), Message: err.Error()}
		}
		if e := json.NewEncoder(os.Stdout).Encode(out); e != nil {
			return 1
		}
	} else if err != nil {
		operatorPrintError(os.Stderr, err)
	} else if value != nil {
		switch v := value.(type) {
		case string:
			fmt.Println(v)
		default:
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
		}
	}
	if err != nil {
		return 1
	}
	return 0
}

// Keep the real operator command's JSON exit/error contract testable without
// invoking privileged systemd/network operations in CLI unit tests. Verified
// partial effects must be serialized even when a later step fails.
func outputStatus(j bool, report sc.Status, err error) int {
	if err != nil && report.Desired == "" {
		return output(j, nil, err)
	}
	if j || err == nil {
		return output(j, report, err)
	}
	if output(false, report, nil) != 0 {
		return 1
	}
	operatorPrintError(os.Stderr, err)
	return 1
}

// The status command uses a read-only getter so both human and JSON result
// paths can be tested independently of a live host's systemd bus.
func runStatus(j bool, read func() (sc.Status, error)) int {
	status, err := read()
	return outputStatus(j, status, err)
}

// Host drift is an explicit operator diagnostic: on an observed failure,
// retain component-level evidence in the interactive and text CLI, without
// changing the shared error semantics of unrelated commands.
func outputHostDrift(j bool, report sc.HostDriftReport, err error) int {
	if report.Mode == "" {
		return output(j, nil, err)
	}
	if !j && err != nil {
		if output(false, report, nil) != 0 {
			return 1
		}
		operatorPrintError(os.Stderr, err)
		return 1
	}
	return output(j, report, err)
}
func parseOpts(args []string) (bool, *sc.Manager, []string, error) {
	opts := flag.NewFlagSet("server-connect", flag.ContinueOnError)
	opts.SetOutput(io.Discard)
	jsonOut := opts.Bool("json", false, "JSON output")
	stateDir := opts.String("state-dir", sc.DefaultDir, "private state folder")
	core := opts.String("core", sc.DefaultCore, "pinned sing-box executable")
	port := opts.Int("port", sc.DefaultPort, "loopback proxy port")
	if e := opts.Parse(args); e != nil {
		return *jsonOut, nil, nil, sc.Fault("invalid_arguments", "invalid or unsupported command options")
	}
	if *port < 1 || *port > 65535 {
		return *jsonOut, nil, nil, sc.Fault("invalid_arguments", "invalid local proxy port")
	}
	return *jsonOut, sc.New(*stateDir, *core, *port), opts.Args(), nil
}
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, sc.MaxProfileBytes+1))
	}
	if strings.Contains(path, "://") {
		return nil, sc.Fault("invalid_input", "--file expects a local path or '-', not a URI; provide the secret on stdin")
	}
	f, e := os.Open(path)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return nil, sc.Fault("file_not_found", "profile file not found; check the private local path")
		}
		return nil, sc.Fault("file_unreadable", "profile file could not be opened (path withheld)")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, sc.MaxProfileBytes+1))
	if e != nil {
		return nil, sc.Fault("file_unreadable", "profile file could not be read")
	}
	return b, nil
}
func run(j bool, m *sc.Manager, args []string) int {
	if len(args) == 0 {
		return menu(m)
	}
	name := args[0]
	args = args[1:]
	// Simple root-level JSON behavior; do not intercept flags passed to child commands.
	if name != "exec" {
		rest := []string{}
		for _, x := range args {
			if x == "--json" {
				j = true
			} else {
				rest = append(rest, x)
			}
		}
		args = rest
	}
	switch name {
	case "installer-check-target":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		manifest := opts.String("manifest", "", "verified local bundle manifest")
		if err := opts.Parse(args); err != nil || len(opts.Args()) != 0 || *manifest == "" || os.Geteuid() != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installer-only target check requires --manifest FILE"))
		}
		report, err := sc.VerifyInstallerTarget(*manifest)
		return output(j, report, err)
	case "installer-check-guard-clear":
		if len(args) != 0 || os.Geteuid() != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installer-only command"))
		}
		err := m.InstallerCheckGuardClear()
		return output(j, map[string]bool{"guard_clear": err == nil}, err)
	case "installer-check-service":
		if len(args) != 0 || os.Geteuid() != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installer-only command"))
		}
		err := m.VerifyUnitForInstaller()
		return output(j, map[string]bool{"verified": err == nil}, err)
	case "installer-reconcile-direct":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installer-only command"))
		}
		err := m.ReconcileDirectUnderInstaller()
		return output(j, map[string]bool{"direct_reconciled": err == nil}, err)
	case "version":
		return output(j, map[string]string{"manager": managerVersion, "sing_box": sc.CoreVersion}, nil)
	case "smart-routing-data":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "smart-routing-data takes no options"))
		}
		report, err := sc.BundledIranGeoSnapshotStatus()
		return output(j, report, err)
	case "status":
		return runStatus(j, m.Status)
	case "connect-smart":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		underlay := opts.String("underlay-if", "", "the host network underlay interface")
		tun := opts.String("tunnel-if", "sctun0", "dedicated Server Connect TUN name")
		ipv4 := opts.String("tunnel-ipv4", "172.31.99.1/30", "dedicated private IPv4 TUN CIDR")
		ipv6 := opts.String("tunnel-ipv6", "fd73:99::1/64", "dedicated private IPv6 TUN CIDR")
		mode := opts.String("mode", "bypass_iran", "default|bypass_iran")
		healthThreshold := opts.Int("health-failures", 3, "positive consecutive selected HTTPS failure rounds before Direct/off")
		healthQA := opts.Bool("health-synthetic-qa", false, "synthetic-only HTTPS fixture; not field proof")
		selectedIPv6 := opts.Bool("enable-selected-ipv6", false, "allow IPv6 via VPN only after selected exit IPv6 capability is verified")
		iranCoverage := opts.String("iran-coverage", "consensus", "consensus (DB-IP and Chocolate4U agreement) or dbip")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 || *underlay == "" {
			return output(j, nil, sc.Fault("invalid_arguments", "connect-smart requires --underlay-if"))
		}
		report, e := m.ConnectNativeSmartRouting(sc.NativePolicyOptions{
			InterfaceName: *tun, UnderlayInterface: *underlay,
			IPv4Address: *ipv4, IPv6Address: *ipv6, Mode: *mode,
			HealthFailureThreshold: *healthThreshold, HealthSyntheticQA: *healthQA,
			EnableSelectedIPv6: *selectedIPv6, IranCoverage: *iranCoverage,
		})
		return output(j, report, e)
	case "native-status":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "native-status takes no options"))
		}
		report, e := m.NativeStatus()
		return output(j, report, e)
	case "native-preflight":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installed native service preflight takes no options"))
		}
		e := m.NativePreflightInstalled()
		return output(j, map[string]bool{"native_preflight_ok": e == nil}, e)
	case "native-recover":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "installed native service recovery takes no options"))
		}
		e := m.NativeRecoverInstalled()
		return output(j, map[string]bool{"native_recovery_verified": e == nil}, e)
	case "smart-routing-rules":
		return runSmartRoutingRules(j, m, args)
	case "mode-overview":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "mode-overview accepts no command options"))
		}
		return runModeOverview(j, m.Status)
	case "activation-journal-status":
		if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "activation-journal-status accepts no command options"))
		}
		report, err := m.InspectActivationJournal()
		if err != nil {
			return output(j, nil, err) // never serialize untrusted/private journal evidence
		}
		return output(j, report, nil)
	case "list", "profiles":
		s, e := m.List()
		return output(j, s, e)
	case "import", "validate":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		f := opts.String("file", "-", "config file, VLESS link file, or - for stdin")
		tag := opts.String("tag", "", "sing-box outbound tag")
		if e := opts.Parse(args); e != nil {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid command options"))
		}
		b, e := readInput(*f)
		if e != nil {
			return output(j, nil, e)
		}
		if name == "validate" {
			p, e := sc.ValidateSource(b, *tag)
			if e != nil {
				return output(j, nil, e)
			}
			if e = sc.EnsureCore(m.Core); e != nil {
				return output(j, nil, e)
			}
			cfg, e := sc.CoreConfig(p, m.Port, "ephemeral-validation-only")
			if e == nil {
				e = sc.CheckConfig(m.Core, os.TempDir(), cfg)
			}
			return output(j, map[string]any{"valid": e == nil, "kind": p.Kind, "validation_level": "pinned_core_config", "network_verified": false}, e)
		}
		p, e := m.Import(b, *tag)
		return output(j, p, e)
	case "select", "remove":
		if len(args) != 1 {
			return output(j, nil, errors.New(name+" requires one profile ID"))
		}
		var e error
		if name == "select" {
			e = m.Select(args[0])
		} else {
			e = m.Remove(args[0])
		}
		return output(j, map[string]any{"profile_id": args[0], "action": name}, e)
	case "ready":
		e := m.Ready()
		return output(j, map[string]any{"local_listener_ready": e == nil, "upstream_reachability": "not_tested"}, e)
	case "connect":
		e := m.Connect()
		return output(j, "Proxy Only connection requested; use probe to verify upstream reachability", e)
	case "disconnect":
		e := m.Disconnect()
		return output(j, "Direct mode restored after owned-service cleanup", e)
	case "probe", "test":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		via := opts.String("via", "proxy", "direct or proxy (no fallback)")
		target := opts.String("url", "", "HTTP(S) target")
		if e := opts.Parse(args); e != nil {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid command options"))
		}
		if *target == "" {
			return output(j, nil, sc.Fault("invalid_arguments", "--url is required"))
		}
		res, e := m.Probe(*via, *target)
		return output(j, res, e)
	case "native-health-executor":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		qaKill := opts.String("qa-kill-at", "", "disposable-only health publication interruption")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid supervised TUN health options"))
		}
		mode, err := m.NativeHealthGuardMode()
		if err != nil {
			return output(j, nil, err)
		}
		if mode == "native" {
			if *qaKill != "" {
				return output(j, nil, sc.Fault("invalid_arguments", "legacy QA crash injection cannot operate on native guard"))
			}
			report, e := m.RunNativeHealthRound()
			return output(j, report, e)
		}
		if mode == "native_off" {
			e := m.CleanupIdleNativeHealthGuards()
			return output(j, map[string]string{"native_health": "off"}, e)
		}
		return output(j, nil, sc.Fault("guard_pending", "retired v4 Health operation is unsupported; verify owned cleanup before Native activation"))
	case "activation-trial-recover", "activation-trial-status":
		qaPoint, qaFaultPoint := "", ""
		if name == "activation-trial-recover" {
			opts := flag.NewFlagSet(name, flag.ContinueOnError)
			opts.SetOutput(io.Discard)
			point := opts.String("qa-kill-at", "", "disposable-only recovery interruption point")
			fault := opts.String("qa-fail-at", "", "disposable-only v3 recovery error-path injection")
			if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
				return output(j, nil, sc.Fault("invalid_arguments", "invalid rule-trial recovery options"))
			}
			qaPoint = *point
			qaFaultPoint = *fault
		} else if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "rule-trial status accepts no options"))
		}
		if name == "activation-trial-recover" {
			mode, modeErr := m.NativeHealthGuardMode()
			if modeErr != nil {
				return output(j, nil, modeErr)
			}
			if mode == "native" {
				if qaPoint != "" || qaFaultPoint != "" {
					return output(j, nil, sc.Fault("invalid_arguments", "legacy trial fault injection cannot operate on native supervisor"))
				}
				report, e := m.SuperviseNativeHealth()
				return output(j, report, e)
			}
			if mode == "native_off" {
				e := m.CleanupIdleNativeHealthGuards()
				return output(j, map[string]string{"native_health": "off"}, e)
			}
			receipt, err := m.RecoverGuardedRuleTrial(qaPoint, qaFaultPoint)
			status := output(j, receipt, err)
			if sc.ErrorCode(err) == "trial_resource_conflict" {
				// Native systemd ExecMainStatus=41 identifies exact foreign
				// kernel-object refusal. Other errors remain ordinary nonzero;
				// no generic service failure can prove the conflict fixture.
				return 41
			}
			return status
		}
		receipt, err := m.InspectGuardedRuleTrial()
		return output(j, receipt, err)
	case "activation-trial-clear":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		id := opts.String("operation-id", "", "exact recovered operation ID")
		revision := opts.Uint64("revision", 0, "exact recovered revision")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 || *revision != 3 {
			return output(j, nil, sc.Fault("invalid_arguments", "clear requires exact recovered revision 3"))
		}
		err := m.ClearRecoveredRuleTrial(*id, *revision)
		return output(j, map[string]any{"operation_id": *id, "cleared": err == nil}, err)
	case "selective-abandon-intent":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		id := opts.String("operation-id", "", "exact previously returned operation ID")
		revision := opts.Uint64("revision", 0, "exact untouched prepared revision")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 || *id == "" || *revision != 1 {
			return output(j, nil, sc.Fault("invalid_arguments", "abandon requires an exact operation ID and prepared revision 1"))
		}
		status, err := m.AbandonSelectiveIntent(*id, *revision)
		if err != nil {
			return output(j, nil, err)
		}
		return output(j, status, nil)
	case "diagnose-path":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		via := opts.String("via", "proxy", "direct or proxy; never falls back")
		var urls []string
		opts.Func("url", "HTTP(S) target; repeat for as many distinct hosts as needed", func(value string) error {
			urls = append(urls, value)
			return nil
		})
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid diagnose-path options"))
		}
		result, err := m.DiagnosePath(*via, urls)
		return output(j, result, err)
	case "host-preflight":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		endpoint := opts.String("endpoint", "", "literal VPN endpoint IPv4 or IPv6 address")
		management := opts.String("management-peer", "", "literal SSH/admin peer IPv4 or IPv6 address")
		withNft := opts.Bool("with-nftables", false, "add read-only native nftables fingerprint; never grants ownership")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid host-preflight options"))
		}
		var report sc.HostPreflight
		var err error
		if *withNft {
			report, err = sc.InspectHostRoutesAndFirewall(*endpoint, *management)
		} else {
			report, err = sc.InspectHostRoutes(*endpoint, *management)
		}
		return output(j, report, err)
	case "host-drift":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		baseline := opts.String("baseline", "", "private JSON file from --json host-preflight")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 || *baseline == "" {
			return output(j, nil, sc.Fault("invalid_arguments", "host-drift requires --baseline FILE"))
		}
		report, err := sc.InspectHostDrift(*baseline)
		return outputHostDrift(j, report, err)
	case "underlay-tcp":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		endpoint := opts.String("endpoint", "", "pinned literal TCP endpoint IPv4 or IPv6")
		hostname := opts.String("hostname", "", "optional hostname to resolve and verify matches the pinned endpoint IP")
		port := opts.Int("port", 0, "explicit TCP destination port")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid underlay-tcp options"))
		}
		hostnameProvided := false
		opts.Visit(func(f *flag.Flag) {
			if f.Name == "hostname" {
				hostnameProvided = true
			}
		})
		if hostnameProvided && *hostname == "" {
			return output(j, nil, sc.Fault("invalid_arguments", "explicit --hostname must not be empty"))
		}
		var report sc.UnderlayTCPReport
		var err error
		if !hostnameProvided {
			report, err = sc.InspectUnderlayTCP(*endpoint, *port)
		} else {
			report, err = sc.InspectUnderlayTCPWithHostname(*endpoint, *hostname, *port)
		}
		// No report exists when argument validation fails. Do not encode a
		// zero-value struct with misleading read_only=false safety fields.
		if report.Mode == "" {
			return output(j, nil, err)
		}
		return output(j, report, err)
	case "underlay-dns":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		hostname := opts.String("hostname", "", "absolute DNS-style hostname to verify")
		endpoint := opts.String("endpoint", "", "literal VPN endpoint IPv4 or IPv6")
		resolver := opts.String("resolver", "", "literal explicit DNS resolver IPv4 or IPv6")
		resolverPort := opts.Int("resolver-port", 53, "explicit DNS resolver port")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid underlay-dns options"))
		}
		report, err := sc.InspectUnderlayDNS(*hostname, *endpoint, *resolver, *resolverPort)
		if report.Mode == "" {
			return output(j, nil, err) // Invalid arguments have no diagnostic evidence.
		}
		return output(j, report, err)
	case "apt":
		if j {
			return output(true, nil, sc.Fault("invalid_arguments", "apt streams child output and does not support JSON mode"))
		}
		code, err := m.Apt(args)
		if err != nil {
			return output(false, nil, err)
		}
		return code
	case "exec":
		if j {
			return output(true, nil, errors.New("exec streams child output and does not support JSON mode"))
		}
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}
		code, e := m.Exec(args)
		if e != nil {
			fmt.Fprintln(os.Stderr, "Error:", e)
		}
		if e != nil {
			return 1
		}
		return code
	case "menu":
		return menu(m)
	case "help", "--help", "-h":
		fmt.Print(helpText)
		return 0
	default:
		return output(j, nil, sc.Fault("unknown_command", "unknown command; run help"))
	}
}

const helpText = `Server Connect — offline-first Linux connectivity manager

Usage:
  server-connect [--json] [--state-dir PATH] [--core PATH] COMMAND

Commands:
  menu                       Interactive menu (no machine-output contract)
  mode-overview              Read-only Direct / Proxy Only / Smart Routing availability
  smart-routing-rules list   Inspect saved-only operator Direct/VPN exceptions
  smart-routing-rules add --cidr CIDR --via direct|vpn
  smart-routing-rules add --domain NAME [--suffix] --via vpn
  smart-routing-rules remove --cidr CIDR | --domain NAME [--suffix]
  smart-routing-rules import --source ID --as-of YYYY-MM-DD --sha256 HEX --file FILE|-
                             [--replaces-sha256 HEX] for explicit source replacement
  smart-routing-rules remove-source --source ID --sha256 HEX
  smart-routing-rules preview-native --tunnel-if NAME --underlay-if NAME
                                     --tunnel-ipv4 CIDR [--tunnel-ipv6 CIDR]
                                     [--mode default|bypass_iran]
                                     [--iran-coverage consensus|dbip] [--enable-selected-ipv6]
                              Compiles saved rules with official sing-box;
                              checks Core config only, never activates host TUN
  import [--file FILE|-]      Import one VLESS TCP/WS/HTTPUpgrade URI or
                             supported sing-box outbound/config (private file/stdin)
  validate [--file FILE|-]    Validate against pinned sing-box without saving
  profiles                   List saved profiles (no credentials)
  select ID                  Select a saved profile (disconnect first)
  remove ID                  Remove an inactive profile
  connect                    Start authenticated loopback Proxy Only
  connect-smart --underlay-if NAME [--tunnel-if NAME] [--tunnel-ipv4 CIDR]
                [--tunnel-ipv6 CIDR] [--mode default|bypass_iran]
                [--health-failures POSITIVE_NUMBER] [--health-synthetic-qa]
                [--enable-selected-ipv6] [--iran-coverage consensus|dbip]
                             IPv6 requires verified selected exit; default IR is two-source consensus
                             Start guarded native sing-box Smart Routing
                             Synthetic health only on isolated test hosts
  native-status              Read native service, guard and HTTPS health scope
  native-preflight           Installed systemd ExecStartPre only
  native-recover             Installed systemd ExecStopPost only
  ready                      Verify owned authenticated listener (not upstream)
  disconnect                 Restore Direct from owned Proxy Only/Native TUN
  status [--json]            Desired/observed state, bounded native HTTPS health
  activation-journal-status  Private intent state/operation ID only; no host mutation
  smart-routing-data        Inspect pinned DB-IP/Chocolate4U IR consensus offline
                              Country geolocation is estimated, not proven;
                              no live test, signed-source trust or routing change
  probe --via proxy|direct --url https://example.org
  diagnose-path --via proxy|direct --url https://one.example --url https://two.example
                              One or more distinct hosts; diagnostic only
  exec -- curl -I https://example.org
  apt -- apt-get update        Strict opt-in APT via trusted native binary
  host-preflight [--endpoint IP] [--management-peer IP] [--with-nftables]
                              Observe routes/rules and optionally native nftables;
                              no activation or firewall ownership
  selective-abandon-intent --operation-id HEX32 --revision 1
                              Remove only exact untouched historical PREPARED intent
  native-health-executor      Installed internal Native Health Guard executor
  activation-trial-status     Inspect v2 rule-only or v3 loopback route+rule trial
  activation-trial-recover    Independent native + historical v2/v3 recovery executor
  activation-trial-clear --operation-id HEX32 --revision 3
                              Clear exact recovered v2/v3 experimental trial journal
  host-drift --baseline FILE Compare a prior private preflight JSON with now
                              Nonzero on drift; never authorizes activation
  underlay-tcp --endpoint IP --port N [--hostname NAME]
                              Optional hostname must resolve to pinned IP before interface-bound TCP probe
  underlay-dns --hostname NAME --endpoint IP --resolver IP [--resolver-port 53]
                              Query only the selected interface-bound resolver; never activates routing
  version                    Show pinned versions

Import VLESS links from stdin or a mode-0600 file, not shell argv. 'exec'
sets proxy variables for only the selected child process. 'apt' passes
an anonymous private APT config to a verified native APT child, with no
/etc/apt edits. Put the APT action first, then options, for example:
  apt -- apt-get install -y package
Options before the action and ambiguous short-option groups are refused.
Combined -U/--update package operations are unsupported; run an explicit
strict update first. Neither mode routes unrelated host
traffic globally. Path diagnostics never fall back to Direct, do not echo
targets in results, and do not establish tunnel health or start recovery.
Selected Smart TUN host check binds a literal diagnostic IP to the selected
saved VLESS endpoint, requiring an explicit interface-bound DNS resolver
when the endpoint is a hostname. Success means only that the diagnostic ran;
see reasons and activation_ready=false even when all observed paths work.
It never changes routes, services, firewall, DNS or profile settings.
Host preflight is observational: a route lookup does not
prove connectivity, safety, routing ownership or readiness to activate TUN.
The --with-nftables option adds a privacy-preserving read-only firewall
fingerprint when trusted native nftables inspection is available. It cannot
prove firewall ownership, prevent concurrent changes or authorize TUN Apply.
Host drift compares separate, non-atomic network observations without changing
the host, and is never an activation guard or a recovery journal.
Activation-journal-status shows only safe metadata for the internal v1
PREPARED/UNCERTAIN journal, never private resource before/intended snapshots.
Historical v1 selective staging and v2/v3 rule/route trial creation are
retired; no new legacy host route policy can be created by the CLI.
Only selective-abandon-intent can remove an exact unarmed historical v1
PREPARED operation. UNCERTAIN or modified journals remain untouched; legacy
v2/v3 pending/recovered records retain strict ownership-aware recovery and
exact recovered clearance. An absent journal does not prove safe networking.
The retired v4 disposable TUN Apply/Confirm/Disconnect experimental
CLI is no longer available. The product's actual Smart Routing path is
connect-smart + native-status + disconnect, with the independently supervised
Native Health/Recovery systemd roles retained. Historical journal recovery
does not authorize activating or trusting old trials.
An explicit underlay-tcp probe binds a TCP socket to the kernel-selected
interface and sends no application data. With --hostname, current host name
resolution must include the explicit pinned --endpoint IP before TCP probing.
This is not proof that resolver traffic bypassed a VPN or that DNS bootstrap,
SSH/hosted ingress, VPN protocol, ownership or guards are safe.
Underlay-dns explicitly queries only a pinned DNS resolver through the
kernel-selected interface and checks its answers against the pinned endpoint.
Even matching answers cannot guarantee future DNS/bootstrap behavior after
routing changes, authenticate DNS, or authorize tunnel activation.
`

func menu(m *sc.Manager) int {
	return menuWithRunner(m, menuRun)
}

// Keeping dispatch explicit makes canceled prompts provably side-effect free
// without opening test sockets or invoking installed host/network commands.
func menuWithRunner(m *sc.Manager, dispatch func(*sc.Manager, ...string) int) int {
	in := bufio.NewReader(os.Stdin)
	ui := terminalPresenter(os.Stdout)
	advanced := false
	for {
		ui.menu(m, advanced)
		raw, e := in.ReadString('\n')
		if e != nil {
			return 0
		}
		choice := strings.TrimSpace(raw)
		switch choice {
		case "a", "A":
			advanced = !advanced
			continue
		case "0", "q":
			return 0
		case "1":
			dispatch(m, []string{"status"}...)
		case "18":
			dispatch(m, []string{"mode-overview"}...)
		case "22":
			dispatch(m, []string{"native-status"}...)
		case "21":
			// This is the same guarded native action as the CLI, not the
			// isolated historical TUN trial. Host admission, ownership and
			// independent recovery are validated inside connect-smart.
			fmt.Println("Guarded native Smart Routing is a QA candidate, NOT approved for general-host/production use.")
			fmt.Println("This may change host-wide routing. Use only on an authorized disposable host with console recovery.")
			underlay, ok := operatorPrompt(in, "Current underlay interface (from 'ip route', or cancel): ", false)
			if !ok {
				continue
			}
			fmt.Println("Policy:")
			fmt.Println("  1 DB-IP + Chocolate4U consensus Direct; other public traffic via VPN")
			fmt.Println("  2 All public traffic, including Iran, via VPN")
			fmt.Println("    Protected/private and explicit Direct exceptions remain Direct")
			fmt.Print("Choose policy 1 or 2 (or cancel): ")
			policy, err := in.ReadString('\n')
			if err != nil {
				fmt.Println("Canceled: incomplete policy; no connection started")
				continue
			}
			mode := ""
			switch strings.TrimSpace(policy) {
			case "1":
				mode = "bypass_iran"
			case "2":
				mode = "default"
			default:
				fmt.Println("Canceled: choose policy 1 or 2; no connection started")
				continue
			}
			fmt.Println("A running Core alone does not prove VPN transit, routing safety, or release readiness.")
			fmt.Print("Activate independent guards and native host routing? Type CONNECT-SMART: ")
			ack, err := in.ReadString('\n')
			if err != nil || strings.TrimSpace(ack) != "CONNECT-SMART" {
				fmt.Println("Canceled: no connection started")
				continue
			}
			if dispatch(m, "connect-smart", "--underlay-if", underlay, "--mode", mode) == 0 {
				fmt.Println("Core started under native guards; independently check selected VPN/Direct traffic.")
				fmt.Println("Inspect option 22 (native-status), or choose option 7 to return to Direct.")
			}
		case "19":
			fmt.Print("Routing Rules: 1 List  2 Add CIDR  3 Add VPN Domain  4 Import List  5 Remove CIDR  6 Remove Domain  7 Remove Source: ")
			operation, err := in.ReadString('\n')
			if err != nil {
				return 0
			}
			switch strings.TrimSpace(operation) {
			case "1":
				dispatch(m, []string{"smart-routing-rules", "list"}...)
			case "2", "3", "5", "6":
				value, ok := operatorPrompt(in, "Canonical CIDR or domain value (or cancel): ", false)
				if !ok {
					continue
				}
				name := strings.TrimSpace(operation)
				op := "add"
				if name == "5" || name == "6" {
					op = "remove"
				}
				command := []string{"smart-routing-rules", op}
				if name == "2" || name == "5" {
					command = append(command, "--cidr", value)
				} else {
					mode, ok := operatorPrompt(in, "Suffix match (y/N, or cancel): ", true)
					if !ok {
						continue
					}
					if mode != "" && !strings.EqualFold(mode, "y") && !strings.EqualFold(mode, "n") {
						fmt.Println("Canceled: choose y or n; no rule action started")
						continue
					}
					command = append(command, "--domain", value)
					if strings.EqualFold(mode, "y") {
						command = append(command, "--suffix")
					}
				}
				if op == "add" {
					via := "vpn"
					if name == "2" {
						answer, ok := operatorPrompt(in, "Route via direct or vpn (or cancel): ", false)
						if !ok {
							continue
						}
						if answer != "direct" && answer != "vpn" {
							fmt.Println("Canceled: choose direct or vpn; no rule action started")
							continue
						}
						via = answer
					}
					command = append(command, "--via", via)
				}
				dispatch(m, command...)
			case "4":
				file, ok := operatorPrompt(in, "Local list file path (use CLI for stdin, or cancel): ", false)
				if !ok {
					continue
				}
				if strings.TrimSpace(file) == "-" {
					fmt.Println("Menu cannot import stdin; use server-connect smart-routing-rules import --file - instead")
					continue
				}
				source, ok := operatorPrompt(in, "Source label (lowercase a-z, 0-9, -, _, or cancel): ", false)
				if !ok {
					continue
				}
				date, ok := operatorPrompt(in, "Source as-of date (YYYY-MM-DD, or cancel): ", false)
				if !ok {
					continue
				}
				digest, ok := operatorPrompt(in, "Independently supplied SHA-256 of raw list (or cancel): ", false)
				if !ok {
					continue
				}
				prior, ok := operatorPrompt(in, "Expected prior source SHA-256 for replacement (blank for new): ", true)
				if !ok {
					continue
				}
				args := []string{"smart-routing-rules", "import", "--file", strings.TrimSpace(file),
					"--source", strings.TrimSpace(source), "--as-of", strings.TrimSpace(date), "--sha256", strings.TrimSpace(digest)}
				if previous := strings.TrimSpace(prior); previous != "" {
					args = append(args, "--replaces-sha256", previous)
				}
				dispatch(m, args...)
			case "7":
				source, ok := operatorPrompt(in, "Existing source label (or cancel): ", false)
				if !ok {
					continue
				}
				digest, ok := operatorPrompt(in, "Exact current source SHA-256 (or cancel): ", false)
				if !ok {
					continue
				}
				dispatch(m, []string{"smart-routing-rules", "remove-source", "--source", strings.TrimSpace(source), "--sha256", strings.TrimSpace(digest)}...)
			default:
				fmt.Println("Unknown routing rule action; no changes made")
			}
		case "2":
			dispatch(m, []string{"profiles"}...)
		case "3":
			path, ok := operatorPrompt(in, "Private local config file path (or cancel): ", false)
			if !ok {
				continue
			}
			dispatch(m, "import", "--file", path)
		case "4", "8":
			id, ok := operatorPrompt(in, "Profile ID (or cancel): ", false)
			if !ok {
				continue
			}
			if choice == "4" {
				dispatch(m, "select", id)
			} else {
				ack, ok := operatorPrompt(in, "Remove this saved profile? Type REMOVE: ", false)
				if !ok || ack != "REMOVE" {
					fmt.Println("Canceled: saved profile unchanged")
					continue
				}
				dispatch(m, "remove", id)
			}
		case "5":
			dispatch(m, []string{"connect"}...)
		case "6":
			url, ok := operatorPrompt(in, "Test URL (https://..., or cancel): ", false)
			if !ok {
				continue
			}
			path, ok := operatorPrompt(in, "Path 1=proxy, 2=direct: ", false)
			if !ok || (path != "1" && path != "2") {
				fmt.Println("Canceled: choose an explicit path; no network probe started")
				continue
			}
			via := "proxy"
			if path == "2" {
				via = "direct"
			}
			dispatch(m, "probe", "--via", via, "--url", url)
		case "7":
			dispatch(m, []string{"disconnect"}...)
		case "10":
			advanced = true
			dispatch(m, []string{"host-preflight"}...)
		case "17":
			advanced = true
			dispatch(m, []string{"host-preflight", "--with-nftables"}...)
		case "11":
			advanced = true
			fmt.Println("Enter HTTP(S) targets with distinct hostnames; blank finishes, cancel aborts.")
			var targets []string
			canceled := false
			for {
				target, ok := operatorPrompt(in, "HTTP(S) target (blank to finish, or cancel): ", true)
				if !ok {
					canceled = true
					break
				}
				if target == "" {
					break
				}
				targets = append(targets, target)
			}
			if canceled || len(targets) == 0 {
				fmt.Println("Canceled: no network diagnostic started")
				continue
			}
			selection, ok := operatorPrompt(in, "Path 1=proxy, 2=direct (or cancel): ", false)
			if !ok || (selection != "1" && selection != "2") {
				fmt.Println("Canceled: choose an explicit path; no network diagnostic started")
				continue
			}
			via := "proxy"
			if selection == "2" {
				via = "direct"
			}
			command := []string{"diagnose-path", "--via", via}
			for _, target := range targets {
				command = append(command, "--url", target)
			}
			dispatch(m, command...)
		case "13":
			advanced = true
			address, ok := operatorPrompt(in, "Literal TCP endpoint IP (no DNS): ", false)
			if !ok {
				continue
			}
			rawPort, ok := operatorPrompt(in, "Endpoint TCP port: ", false)
			if !ok {
				continue
			}
			hostname, ok := operatorPrompt(in, "Optional DNS hostname to verify against pinned IP (blank to skip): ", true)
			if !ok {
				continue
			}
			command := []string{"underlay-tcp", "--endpoint", strings.TrimSpace(address), "--port", strings.TrimSpace(rawPort)}
			if h := strings.TrimSpace(hostname); h != "" {
				command = append(command, "--hostname", h)
			}
			dispatch(m, command...)
		case "14":
			advanced = true
			host, ok := operatorPrompt(in, "Endpoint DNS hostname: ", false)
			if !ok {
				continue
			}
			endpoint, ok := operatorPrompt(in, "Pinned endpoint IP: ", false)
			if !ok {
				continue
			}
			resolver, ok := operatorPrompt(in, "Explicit resolver IP (DNS queries are sent to this resolver): ", false)
			if !ok {
				continue
			}
			dispatch(m, []string{"underlay-dns", "--hostname", strings.TrimSpace(host),
				"--endpoint", strings.TrimSpace(endpoint), "--resolver", strings.TrimSpace(resolver)}...)
		case "16":
			advanced = true
			dispatch(m, []string{"activation-journal-status"}...)
		case "15":
			advanced = true
			path, ok := operatorPrompt(in, "Private host-preflight JSON baseline path: ", false)
			if !ok {
				continue
			}
			dispatch(m, "host-drift", "--baseline", path)
		case "9":
			fmt.Print("APT update refreshes system package indexes using the selected proxy. Type UPDATE to confirm: ")
			confirmation, err := in.ReadString('\n')
			if err != nil || strings.TrimSpace(confirmation) != "UPDATE" {
				fmt.Println("Canceled; no APT action taken")
				continue
			}
			code, err := m.Apt([]string{"apt-get", "update"})
			if err != nil {
				operatorPrintError(os.Stderr, err)
			} else if code != 0 {
				fmt.Fprintf(os.Stderr, "APT exited with status %d; package state may have changed. Inspect APT logs and status before retrying.\n", code)
			} else {
				fmt.Println("APT command completed; check package-index results above.")
			}
		default:
			if _, e := strconv.Atoi(choice); e == nil {
				fmt.Println("Unknown option. Choose a displayed number or 'a' for advanced tools; nothing changed.")
			} else {
				fmt.Println("Enter a displayed menu number, 'a' for advanced tools, or '0' to exit; nothing changed.")
			}
		}
	}
}

func main() {
	// Determine JSON preference before parsing so invalid flags stay machine-readable.
	wantsJSON := false
	for _, arg := range os.Args[1:] {
		if arg == "--json" {
			wantsJSON = true
			break
		}
		if arg == "exec" {
			break
		}
	}
	jsonOut, m, args, e := parseOpts(os.Args[1:])
	if e != nil {
		output(wantsJSON || jsonOut, nil, e)
		os.Exit(2)
	}
	os.Exit(run(jsonOut, m, args))
}
