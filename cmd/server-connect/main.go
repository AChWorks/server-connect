// Server Connect is a minimal local CLI; it does not own the host routing table.
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
		fmt.Fprintln(os.Stderr, "Error:", err)
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

// Status may fail after safely loading desired state. Keep that bounded
// diagnostic visible for operators without changing unrelated CLI errors.
// An unavailable state load has no trustworthy partial report to display.
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
	fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", sc.ErrorCode(err), err)
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
		fmt.Fprintf(os.Stderr, "Error [%s]: %v\n", sc.ErrorCode(err), err)
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
	if *port < 1024 || *port > 65535 {
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
	case "status":
		return runStatus(j, m.Status)
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
		return output(j, "Direct mode restored; no host routes or firewall settings were touched", e)
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
	case "selective-plan", "selective-stage-intent":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		endpoint := opts.String("endpoint", "", "literal existing VPN endpoint IP")
		management := opts.String("management-peer", "", "literal current SSH/admin peer IP")
		tunnel := opts.String("tunnel-if", "", "proposed unused TUN interface name")
		var destinations destinationFlags
		opts.Var(&destinations, "destination", "explicit public CIDR; repeat per destination")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid selective planning/staging options"))
		}
		request := sc.SelectivePlanRequest{
			EndpointIP: *endpoint, ManagementPeerIP: *management,
			TunnelInterface: *tunnel, Destinations: destinations,
		}
		if name == "selective-stage-intent" {
			status, err := m.StageSelectiveIntent(request)
			if err != nil {
				return output(j, nil, err)
			}
			return output(j, status, nil)
		}
		plan, err := sc.PreviewSelectiveRoutes(request)
		if err != nil {
			return output(j, nil, err)
		}
		return output(j, plan, nil)
	case "selective-verify-intent":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		id := opts.String("operation-id", "", "exact previously staged operation ID")
		revision := opts.Uint64("revision", 0, "exact PREPARED revision")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 || *id == "" || *revision != 1 {
			return output(j, nil, sc.Fault("invalid_arguments", "verification requires an exact operation ID and PREPARED revision 1"))
		}
		check, err := m.VerifySelectiveIntentLive(*id, *revision)
		if err != nil {
			return output(j, nil, err)
		}
		return output(j, check, nil)
	case "activation-trial-recover", "activation-trial-status":
		qaPoint := ""
		if name == "activation-trial-recover" {
			opts := flag.NewFlagSet(name, flag.ContinueOnError)
			opts.SetOutput(io.Discard)
			point := opts.String("qa-kill-at", "", "disposable-only recovery interruption point")
			if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
				return output(j, nil, sc.Fault("invalid_arguments", "invalid rule-trial recovery options"))
			}
			qaPoint = *point
		} else if len(args) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "rule-trial status accepts no options"))
		}
		if name == "activation-trial-recover" {
			receipt, err := m.RecoverGuardedRuleTrial(qaPoint)
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
	case "selective-trial-apply", "selective-route-trial-apply", "activation-trial-clear":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		id := opts.String("operation-id", "", "exact staged or recovered operation ID")
		revision := opts.Uint64("revision", 0, "exact operation revision")
		deadline := opts.Int("deadline-seconds", 600, "disposable rule trial deadline in seconds")
		interrupt := opts.Bool("qa-kill-after-rule", false, "legacy disposable-only SIGKILL after rule add")
		qaPoint := opts.String("qa-kill-at", "", "disposable-only apply interruption point")
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid rule trial options"))
		}
		if *interrupt && *qaPoint != "" {
			return output(j, nil, sc.Fault("invalid_arguments", "only one QA interruption point is allowed"))
		}
		if *interrupt && name == "selective-route-trial-apply" {
			return output(j, nil, sc.Fault("invalid_arguments", "legacy rule-only interruption option is unavailable for route trials"))
		}
		if name == "activation-trial-clear" {
			if *deadline != 600 || *interrupt || *qaPoint != "" || *revision != 3 {
				return output(j, nil, sc.Fault("invalid_arguments", "clear requires exact recovered revision 3"))
			}
			err := m.ClearRecoveredRuleTrial(*id, *revision)
			return output(j, map[string]any{"operation_id": *id, "cleared": err == nil}, err)
		}
		if *interrupt {
			*qaPoint = "after-add"
		}
		if name == "selective-route-trial-apply" {
			receipt, err := m.BeginGuardedRouteTrial(*id, *revision, *deadline, *qaPoint)
			return output(j, receipt, err)
		}
		receipt, err := m.BeginGuardedRuleTrial(*id, *revision, *deadline, *qaPoint)
		return output(j, receipt, err)
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
		opts.Func("url", "HTTP(S) target; specify two to four distinct hosts", func(value string) error {
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
		if e := opts.Parse(args); e != nil || len(opts.Args()) != 0 {
			return output(j, nil, sc.Fault("invalid_arguments", "invalid host-preflight options"))
		}
		report, err := sc.InspectHostRoutes(*endpoint, *management)
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

const helpText = `Server Connect — minimal offline-first Proxy Only manager

Usage:
  server-connect [--json] [--state-dir PATH] [--core PATH] COMMAND

Commands:
  menu                       Interactive menu (no machine-output contract)
  import [--file FILE|-]      Import VLESS URI or sing-box outbound/config
  validate [--file FILE|-]    Validate against pinned sing-box without saving
  profiles                   List saved profiles (no credentials)
  select ID                  Select a saved profile (disconnect first)
  remove ID                  Remove an inactive profile
  connect                    Start authenticated loopback Proxy Only
  ready                      Verify owned authenticated listener (not upstream)
  disconnect                 Stop and disable product-owned local proxy service
  status [--json]            Desired/observed service state, not fake VPN health
  activation-journal-status  Private intent state/operation ID only; no host mutation
  probe --via proxy|direct --url https://example.org
  diagnose-path --via proxy|direct --url https://one.example --url https://two.example
                              Two to four distinct hosts; diagnostic only
  exec -- curl -I https://example.org
  apt -- apt-get update        Strict opt-in APT via trusted native binary
  host-preflight [--endpoint IP] [--management-peer IP]
                              Observe kernel routes/rules; no activation
  selective-plan --endpoint IP --management-peer IP --tunnel-if NAME
                 --destination CIDR [--destination CIDR...]
                              Advisory selective routing preview; never applies
  selective-stage-intent     Same options as selective-plan; privately persist
                              an unarmed PREPARED intent; never changes routes
  selective-verify-intent --operation-id HEX32 --revision 1
                              Reinspect exact unarmed intent; no activation
  selective-abandon-intent --operation-id HEX32 --revision 1
                              Remove only exact untouched PREPARED intent
  selective-trial-apply --operation-id HEX32 --revision 1 [--deadline-seconds 600]
                              DISPOSABLE DOCKER-ONLY rule-only trial; never VPN activation
  selective-route-trial-apply --operation-id HEX32 --revision 1 [--deadline-seconds 600]
                              DISPOSABLE DOCKER-ONLY lo route + RPDB rule trial; never VPN activation
  activation-trial-status     Inspect only the guarded rule trial state
  activation-trial-recover    Independent systemd trial timeout/reboot recovery
  activation-trial-clear --operation-id HEX32 --revision 3
                              Clear exact recovered rule-trial journal
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
/etc/apt edits. Combined -U/--update package operations are unsupported;
run an explicit strict update first. Neither mode routes unrelated host
traffic globally. Path diagnostics never fall back to Direct, do not echo
targets in results, and do not establish tunnel health or start recovery.
Host preflight is observational: a route lookup does not
prove connectivity, safety, routing ownership or readiness to activate TUN.
Host drift compares separate, non-atomic network observations without changing
the host, and is never an activation guard or a recovery journal.
Activation-journal-status shows only safe metadata for the internal v1
PREPARED/UNCERTAIN journal, never private resource before/intended snapshots.
Selective-stage-intent makes two non-atomic native observations and records
an advisory PREPARED intent; it is NOT a guard, host reservation or TUN start.
Selective-verify-intent performs two fresh, NON-ATOMIC native kernel reads
against the exact journal operation under the Manager lock. Success is an
observation receipt, not a reserved route, owner proof, armed guard, or token
authorizing later apply; external kernel writers are not locked.
Experimental rule-only trial needs a disconnected disposable systemd Docker guest,
preinstalled independent recovery units and an enabled live recovery timer.
It creates one selected-prefix RPDB rule pointing at an EMPTY table. It has
no VPN path, no production activation, no SSH confirmation and no Runtime
Health Guard. It must expire and cannot be used on a real server.
Only selective-abandon-intent can discard the exact untouched revision;
UNCERTAIN and modified journals cannot be abandoned. Even an absent journal
cannot prove safe networking, guard arming or recovery. These commands may
initialize a private state directory/lock but never change host routes.
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
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nServer Connect | 1 Status  2 Profiles  3 Import  4 Select  5 Connect  6 Test  7 Disconnect  8 Remove  9 APT Update  10 Host Preflight  11 Path Diagnostics  12 Selective Plan  13 Underlay TCP  14 Underlay DNS  15 Host Drift  16 Activation Journal  0 Exit")
		fmt.Print("Choice: ")
		raw, e := in.ReadString('\n')
		if e != nil {
			return 0
		}
		choice := strings.TrimSpace(raw)
		switch choice {
		case "0", "q":
			return 0
		case "1":
			run(false, m, []string{"status"})
		case "2":
			run(false, m, []string{"profiles"})
		case "3":
			fmt.Print("Private local config file path: ")
			p, _ := in.ReadString('\n')
			run(false, m, []string{"import", "--file", strings.TrimSpace(p)})
		case "4", "8":
			fmt.Print("Profile ID: ")
			id, _ := in.ReadString('\n')
			if choice == "4" {
				run(false, m, []string{"select", strings.TrimSpace(id)})
			} else {
				run(false, m, []string{"remove", strings.TrimSpace(id)})
			}
		case "5":
			run(false, m, []string{"connect"})
		case "6":
			fmt.Print("Test URL (https://...): ")
			u, _ := in.ReadString('\n')
			fmt.Print("Path 1=proxy, 2=direct: ")
			p, _ := in.ReadString('\n')
			via := "proxy"
			if strings.TrimSpace(p) == "2" {
				via = "direct"
			}
			run(false, m, []string{"probe", "--via", via, "--url", strings.TrimSpace(u)})
		case "7":
			run(false, m, []string{"disconnect"})
		case "10":
			run(false, m, []string{"host-preflight"})
		case "11":
			fmt.Print("First independent HTTP(S) target: ")
			first, _ := in.ReadString('\n')
			fmt.Print("Second independent HTTP(S) target: ")
			second, _ := in.ReadString('\n')
			fmt.Print("Path 1=proxy, 2=direct: ")
			selection, _ := in.ReadString('\n')
			via := "proxy"
			if strings.TrimSpace(selection) == "2" {
				via = "direct"
			}
			run(false, m, []string{"diagnose-path", "--via", via, "--url", strings.TrimSpace(first), "--url", strings.TrimSpace(second)})
		case "12":
			fmt.Print("Pinned VPN endpoint literal IP: ")
			endpoint, _ := in.ReadString('\n')
			fmt.Print("Current admin/SSH peer literal IP: ")
			management, _ := in.ReadString('\n')
			fmt.Print("Proposed unused TUN interface name: ")
			tunnel, _ := in.ReadString('\n')
			fmt.Print("Public destination CIDRs (comma-separated): ")
			raw, _ := in.ReadString('\n')
			args := []string{"selective-plan", "--endpoint", strings.TrimSpace(endpoint),
				"--management-peer", strings.TrimSpace(management), "--tunnel-if", strings.TrimSpace(tunnel)}
			for _, cidr := range strings.Split(strings.TrimSpace(raw), ",") {
				args = append(args, "--destination", strings.TrimSpace(cidr))
			}
			run(false, m, args)
		case "13":
			fmt.Print("Literal TCP endpoint IP (no DNS): ")
			address, err := in.ReadString('\n')
			if err != nil {
				return 0
			}
			fmt.Print("Endpoint TCP port: ")
			rawPort, err := in.ReadString('\n')
			if err != nil {
				return 0
			}
			fmt.Print("Optional DNS hostname to verify against pinned IP (blank to skip): ")
			hostname, err := in.ReadString('\n')
			if err != nil {
				return 0
			}
			command := []string{"underlay-tcp", "--endpoint", strings.TrimSpace(address), "--port", strings.TrimSpace(rawPort)}
			if h := strings.TrimSpace(hostname); h != "" {
				command = append(command, "--hostname", h)
			}
			run(false, m, command)
		case "14":
			fmt.Print("Endpoint DNS hostname: ")
			host, _ := in.ReadString('\n')
			fmt.Print("Pinned endpoint IP: ")
			endpoint, _ := in.ReadString('\n')
			fmt.Print("Explicit resolver IP (DNS queries are sent to this resolver): ")
			resolver, _ := in.ReadString('\n')
			run(false, m, []string{"underlay-dns", "--hostname", strings.TrimSpace(host),
				"--endpoint", strings.TrimSpace(endpoint), "--resolver", strings.TrimSpace(resolver)})
		case "16":
			run(false, m, []string{"activation-journal-status"})
		case "15":
			fmt.Print("Private host-preflight JSON baseline path: ")
			path, err := in.ReadString('\n')
			if err != nil {
				return 0
			}
			if strings.TrimSpace(path) == "" {
				fmt.Println("Canceled; no baseline supplied")
				continue
			}
			run(false, m, []string{"host-drift", "--baseline", strings.TrimSpace(path)})
		case "9":
			fmt.Print("APT update refreshes system package indexes using the selected proxy. Type UPDATE to confirm: ")
			confirmation, err := in.ReadString('\n')
			if err != nil || strings.TrimSpace(confirmation) != "UPDATE" {
				fmt.Println("Canceled; no APT action taken")
				continue
			}
			code, err := m.Apt([]string{"apt-get", "update"})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error:", err)
			} else if code != 0 {
				fmt.Fprintf(os.Stderr, "APT exited with status %d\n", code)
			}
		default:
			if _, e := strconv.Atoi(choice); e == nil {
				fmt.Println("Unknown choice")
			} else {
				fmt.Println("Enter a menu number")
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
