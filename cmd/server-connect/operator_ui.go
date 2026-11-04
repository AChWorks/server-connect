package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/AChWorks/server-connect/internal/sc"
)

// The terminal presenter is deliberately text-first: every state and action is
// understandable without ANSI, a particular font, or an interactive terminal.
// Structured JSON and machine-readable commands never use this presenter.
type operatorPresenter struct {
	out   io.Writer
	color bool
	width int
}

func terminalPresenter(out *os.File) operatorPresenter {
	p := operatorPresenter{out: out, width: 78}
	if n, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && n >= 20 && n <= 500 {
		p.width = n
	}
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled || os.Getenv("TERM") == "dumb" || os.Getenv("TERM") == "" {
		return p
	}
	p.color = isTerminal(out)
	return p
}

// Device file type alone is insufficient: /dev/null is a character device,
// but it is not a terminal. TCGETS is read-only and works on Linux TTY/PTYs.
func isTerminal(out *os.File) bool {
	var term syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, out.Fd(), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&term)))
	return errno == 0
}

func (p operatorPresenter) tint(text, sgr string) string {
	if !p.color {
		return text
	}
	return "\x1b[" + sgr + "m" + text + "\x1b[0m"
}

func (p operatorPresenter) section(title string) {
	fmt.Fprintln(p.out, "\n"+p.tint(title, "1;36"))
}

func (p operatorPresenter) menu(m *sc.Manager, advanced bool) {
	fmt.Fprintln(p.out, "\n"+p.tint("Server Connect", "1;36")+"  "+managerVersion)
	state := p.menuState(m)
	if p.width < 66 && strings.Contains(state, " | ") {
		for _, part := range strings.Split(state, " | ") {
			fmt.Fprintln(p.out, "  "+part)
		}
	} else {
		fmt.Fprintln(p.out, "  "+state)
	}
	fmt.Fprintln(p.out, "  Smart Routing on general Linux hosts: "+p.tint("NOT AVAILABLE", "1;33"))
	p.section("Connection")
	if p.width < 66 {
		fmt.Fprintln(p.out, "  1 Status")
		fmt.Fprintln(p.out, " 18 Mode Overview")
		fmt.Fprintln(p.out, "  5 Connect (Proxy Only)")
		fmt.Fprintln(p.out, "  7 Disconnect (Proxy Only)")
	} else {
		fmt.Fprintln(p.out, "  1 Status         18 Mode Overview")
		fmt.Fprintln(p.out, "  5 Connect (Proxy Only)    7 Disconnect (Proxy Only)")
	}
	p.section("Profiles and policy")
	if p.width < 66 {
		fmt.Fprintln(p.out, "  2 Profiles       3 Import")
		fmt.Fprintln(p.out, "  4 Select         8 Remove")
		fmt.Fprintln(p.out, " 19 Routing Rules")
		fmt.Fprintln(p.out, "  6 Test Connection    9 APT Update")
	} else {
		fmt.Fprintln(p.out, "  2 Profiles       3 Import       4 Select       8 Remove")
		fmt.Fprintln(p.out, " 19 Routing Rules  6 Test Connection  9 APT Update")
	}
	if advanced {
		p.section("Advanced diagnostics (read-only unless clearly marked)")
		if p.width < 66 {
			fmt.Fprintln(p.out, " 11 Path Diagnostics")
			fmt.Fprintln(p.out, " 12 Selective Plan (legacy, no Apply)")
		} else {
			fmt.Fprintln(p.out, " 11 Path Diagnostics  12 Selective Plan")
		}
		fmt.Fprintln(p.out, " 10 Host Preflight   17 Firewall Preflight")
		fmt.Fprintln(p.out, " 15 Host Drift       16 Activation Journal")
		fmt.Fprintln(p.out, " 13 Underlay TCP     14 Underlay DNS")
		fmt.Fprintln(p.out, " 20 Guarded Smart TUN (isolated QA VM ONLY)")
	}
	fmt.Fprintln(p.out, "\n  a Toggle advanced tools    0 Exit    q Quit")
	fmt.Fprint(p.out, p.tint("Choice: ", "36"))
}

// Status() may create the private state directory/lock on first use. A menu
// must not initialize an otherwise untouched installation merely to render a
// header. An existing installed state may be inspected via the manager's
// established service+guard checks; no route/action is inferred from desire.
func (p operatorPresenter) menuState(m *sc.Manager) string {
	// Check for both the state directory and existing manager lock: Status()
	// must not create either resource just to draw a screen for an untouched
	// installation. Actual status is still obtained through Manager.Status().
	for _, path := range []string{m.Dir, filepath.Join(m.Dir, ".lock")} {
		if _, err := os.Lstat(path); err != nil {
			return p.tint("State: not inspected (run Status after setup)", "33")
		}
	}
	status, observationErr := m.Status()
	if status.Desired == "" {
		return p.tint("State: unverified (open Status for diagnostics)", "33")
	}
	view, err := modeOverviewFromStatus(status, observationErr)
	if err != nil || view.DesiredMode == "" {
		return p.tint("State: unverified (open Status for diagnostics)", "33")
	}
	mode := "Direct"
	if view.DesiredMode == "proxy_only" {
		mode = "Proxy Only"
	}
	observed := "unverified"
	if view.ObservedMode == "proxy_only" {
		observed = "local Proxy Only active (VPN path unverified)"
	} else if view.TrialPhase != "" {
		observed = "experimental TUN " + view.TrialPhase + " (not general-host proof)"
	} else if view.ProxyServiceState == "inactive" && observationErr == nil {
		observed = "Proxy Only service inactive (host route unverified)"
	}
	selected := "none"
	if view.SelectedProfileID != "" {
		selected = view.SelectedProfileID
	}
	return "Requested: " + mode + " | Observed: " + observed + " | Profile: " + selected
}

// A newline-terminated reply is required for any prompt that can lead to a
// mutation. EOF, an empty value or a literal cancellation never dispatches.
func operatorPrompt(in *bufio.Reader, question string, allowBlank bool) (string, bool) {
	fmt.Print(question)
	line, err := in.ReadString('\n')
	if err != nil {
		fmt.Println("Canceled: incomplete input; no action started")
		return "", false
	}
	answer := strings.TrimSpace(line)
	if strings.EqualFold(answer, "cancel") || strings.EqualFold(answer, "back") || (!allowBlank && answer == "") {
		fmt.Println("Canceled: no action started")
		return "", false
	}
	return answer, true
}

// One error guide is shared by text CLI and interactive menu. The code and
// original safe error are retained; no statement of rollback success is made
// solely because an operation returned an error.
func operatorErrorGuidance(code string) (state, next string) {
	switch code {
	case "invalid_arguments", "invalid_input", "unknown_command":
		return "Request rejected; actual host state was not inspected by this error.", "Check the input and run 'server-connect help'."
	case "invalid_profile", "unsupported_profile", "selected_profile_unavailable", "file_not_found", "file_unreadable":
		return "The requested profile or input could not be accepted.", "Use 'server-connect profiles' and check the private file or selected profile."
	case "guard_pending", "activation_journal_conflict", "trial_observation_uncertain", "activation_journal_invalid", "activation_journal_unavailable":
		return "A pending or uncertain operation may still own network resources.", "Inspect 'server-connect activation-journal-status' and the guarded TUN status; do not start another Apply."
	case "unsupported_host", "trial_unsupported", "selected_transport_unsupported":
		return "This action is not admitted for the observed host, mode or transport.", "Inspect 'server-connect mode-overview'; do not bypass host or guard checks."
	case "service_conflict", "service_state_unavailable", "service_binary_untrusted", "guard_unavailable":
		return "Service or guard ownership/health could not be verified.", "Inspect 'server-connect status' and the relevant systemd unit before retrying."
	case "routing_rules_invalid", "routing_rules_conflict", "routing_rules_missing":
		return "The routing rule change was refused; the saved rule identity or revision may differ.", "Inspect 'server-connect smart-routing-rules list' and retry with current identities."
	case "routing_rules_hash_mismatch":
		return "The supplied rule list bytes do not match the pinned SHA-256; no import was accepted.", "Recalculate the raw file digest with 'sha256sum' and retry with an independently verified digest."
	case "probe_http", "probe_unavailable", "core_unavailable":
		return "The requested network path has not been proven healthy.", "Inspect 'server-connect status' and use the explicit Direct/Proxy path diagnostics."
	default:
		return "The resulting state is not verified by this error alone.", "Inspect 'server-connect status' and the relevant guard/journal before retrying a state-changing command."
	}
}

func operatorPrintError(out io.Writer, err error) {
	if err == nil {
		return
	}
	code := sc.ErrorCode(err)
	state, next := operatorErrorGuidance(code)
	heading := "Error [" + code + "]:"
	if terminal, ok := out.(*os.File); ok {
		heading = terminalPresenter(terminal).tint(heading, "1;31")
	}
	fmt.Fprintf(out, "%s %s\nState: %s\nNext: %s\n", heading, err, state, next)
}

func menuRun(m *sc.Manager, command ...string) int {
	if len(command) == 0 {
		return 1
	}
	ui := terminalPresenter(os.Stdout)
	fmt.Printf("\nRunning %s (reported results are scoped to this command):\n", command[0])
	code := run(false, m, command)
	if code == 0 {
		fmt.Println(ui.tint("Completed:", "1;32") + " command succeeded. This is not independent VPN path proof.")
	} else {
		fmt.Println(ui.tint("Not completed:", "1;31") + " inspect the error and current state before retrying.")
	}
	return code
}
