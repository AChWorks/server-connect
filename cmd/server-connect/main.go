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
			out.Error = &apiError{Code: "operation_failed", Message: err.Error()}
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
func parseOpts(args []string) (bool, *sc.Manager, []string, error) {
	opts := flag.NewFlagSet("server-connect", flag.ContinueOnError)
	opts.SetOutput(io.Discard)
	jsonOut := opts.Bool("json", false, "JSON output")
	stateDir := opts.String("state-dir", sc.DefaultDir, "private state folder")
	core := opts.String("core", sc.DefaultCore, "pinned sing-box executable")
	unit := opts.String("unit", sc.DefaultUnit, "owned systemd unit")
	port := opts.Int("port", sc.DefaultPort, "loopback proxy port")
	if e := opts.Parse(args); e != nil {
		return false, nil, nil, e
	}
	if *port < 1024 || *port > 65535 {
		return false, nil, nil, errors.New("invalid local proxy port")
	}
	return *jsonOut, sc.New(*stateDir, *core, *unit, *port), opts.Args(), nil
}
func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(os.Stdin, sc.MaxProfileBytes+1))
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, sc.MaxProfileBytes+1))
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
	case "version":
		return output(j, map[string]string{"manager": managerVersion, "sing_box": sc.CoreVersion}, nil)
	case "status":
		s, e := m.Status()
		return output(j, s, e)
	case "list", "profiles":
		s, e := m.List()
		return output(j, s, e)
	case "import", "validate":
		opts := flag.NewFlagSet(name, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		f := opts.String("file", "-", "config file, VLESS link file, or - for stdin")
		tag := opts.String("tag", "", "sing-box outbound tag")
		if e := opts.Parse(args); e != nil {
			return output(j, nil, e)
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
			return output(j, map[string]any{"valid": e == nil, "kind": p.Kind}, e)
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
			return output(j, nil, e)
		}
		if *target == "" {
			return output(j, nil, errors.New("--url is required"))
		}
		res, e := m.Probe(*via, *target)
		return output(j, res, e)
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
		return output(j, nil, fmt.Errorf("unknown command: %s (run help)", name))
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
  probe --via proxy|direct --url https://example.org
  exec -- curl -I https://example.org
  version                    Show pinned versions

Import VLESS links from stdin or a mode-0600 file, not shell argv. 'exec'
sets proxy variables for only the selected child process, never APT or
system-wide settings. No traffic is routed globally in this version.
`

func menu(m *sc.Manager) int {
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Println("\nServer Connect | 1 Status  2 Profiles  3 Import  4 Select  5 Connect  6 Test  7 Disconnect  8 Remove  0 Exit")
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
	jsonOut, m, args, e := parseOpts(os.Args[1:])
	if e != nil {
		fmt.Fprintln(os.Stderr, "Error:", e)
		os.Exit(2)
	}
	os.Exit(run(jsonOut, m, args))
}
