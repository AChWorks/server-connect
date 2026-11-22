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

// A real interactive terminal can redraw an isolated full-screen menu. Plain
// pipes, scripts and TERM=dumb continue to receive ordinary text without ANSI.
func operatorFullScreen(in, out *os.File) bool {
	return os.Getenv("TERM") != "" && os.Getenv("TERM") != "dumb" && isTerminal(in) && isTerminal(out)
}

func operatorTerminalColumns(out *os.File, fallback int) int {
	var size struct{ row, col, xpixel, ypixel uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, out.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&size)))
	if errno == 0 && size.col >= 20 {
		return int(size.col)
	}
	return fallback
}

// Wrap visible words without trimming task labels. This is deliberately
// UTF-8/rune safe; terminal SGR is applied only after line breaking.
func (p operatorPresenter) printWrapped(indent, content string) {
	p.printWrappedColor(indent, content, "")
}

func (p operatorPresenter) printWrappedColor(indent, content, sgr string) {
	width := p.width
	if width < 20 {
		width = 20
	}
	capacity := width - len([]rune(indent))
	if capacity < 1 {
		capacity = 1
	}
	words := strings.Fields(content)
	line := ""
	emit := func() {
		printed := indent + line
		if sgr != "" {
			printed = p.tint(printed, sgr)
		}
		fmt.Fprintln(p.out, printed)
		line = ""
	}
	for _, word := range words {
		chars := []rune(word)
		for len(chars) > 0 {
			if line != "" {
				if len([]rune(line))+1+len(chars) <= capacity {
					line += " " + string(chars)
					chars = nil
					continue
				}
				emit()
			}
			if len(chars) <= capacity {
				line = string(chars)
				chars = nil
			} else {
				line = string(chars[:capacity])
				emit()
				chars = chars[capacity:]
			}
		}
	}
	if line != "" {
		emit()
	}
}

func (p operatorPresenter) menuRow(labels ...string) {
	combined := "  " + strings.Join(labels, "    ")
	if len([]rune(combined)) <= p.width {
		fmt.Fprintln(p.out, combined)
		return
	}
	for _, label := range labels {
		p.printWrapped("  ", label)
	}
}

func (p operatorPresenter) tint(text, sgr string) string {
	if !p.color {
		return text
	}
	return "\x1b[" + sgr + "m" + text + "\x1b[0m"
}

func (p operatorPresenter) section(title string) {
	if p.width >= 40 {
		fmt.Fprintln(p.out)
	}
	fmt.Fprintln(p.out, p.tint(title, "1;36"))
}

func (p operatorPresenter) menu(m *sc.Manager, advanced bool) {
	fmt.Fprintln(p.out, p.tint("Server Connect", "1;36")+"  "+managerVersion)
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	p.printWrapped("  ", "Host: "+host)
	state := p.menuState(m)
	if strings.Contains(state, "unverified") || strings.Contains(state, "not inspected") || strings.Contains(state, "degraded") {
		p.printWrappedColor("  ", state, "33")
	} else {
		p.printWrapped("  ", state)
	}
	if advanced {
		p.section("Advanced tools")
		p.menuRow("11 Path Diagnostics")
		p.menuRow("10 Host Preflight", "17 Firewall Preflight")
		p.menuRow("15 Host Drift", "16 Activation Journal")
		p.menuRow("13 Underlay TCP", "14 Underlay DNS")
		fmt.Fprintln(p.out)
		p.menuRow("a Back to main", "0 Exit", "q Quit")
	} else {
		if strings.Contains(managerVersion, "-dev") {
			p.printWrappedColor("  ", "Smart: NOT RELEASE-READY (development build)", "1;33")
		} else {
			p.printWrappedColor("  ", "Smart: first activation requires new SSH confirmation", "33")
		}
		p.section("Connection")
		if p.width < 50 {
			p.menuRow("1 Status", "18 Modes")
			p.menuRow("5 Proxy Only", "21 Smart Routing")
			p.menuRow("7 Disconnect", "22 Guard Status")
			p.section("Profiles and settings")
			p.menuRow("2 Profiles", "3 Import")
			p.menuRow("4 Select", "8 Remove")
			p.menuRow("19 Routing Rules", "6 Test")
			p.menuRow("9 APT Update")
		} else {
			smartLabel := "21 Smart Routing (guarded)"
			if strings.Contains(managerVersion, "-dev") {
				smartLabel = "21 Smart Routing (guarded QA)"
			}
			p.menuRow("1 Status", "18 Mode Overview")
			p.menuRow("5 Connect (Proxy Only)", smartLabel)
			p.menuRow("7 Disconnect / Return to Direct", "22 Native Guard / Recovery Status")
			p.section("Profiles and routing")
			p.menuRow("2 Profiles", "3 Import", "4 Select", "8 Remove")
			p.menuRow("19 Routing Rules", "6 Test Connection", "9 APT Update")
		}
		fmt.Fprintln(p.out)
		p.menuRow("a Advanced tools", "0 Exit", "q Quit")
	}
	fmt.Fprint(p.out, p.tint("Choice: ", "36"))
}

// Status() may create the private state directory/lock on first use. A menu
// must not initialize an otherwise untouched installation merely to render a
// header. An existing installed state may be inspected via the manager's
// established service+guard checks; no route/action is inferred from desire.
func (p operatorPresenter) menuState(m *sc.Manager) string {
	// Drawing the menu must not initialize previously absent private state.
	for _, path := range []string{m.Dir, filepath.Join(m.Dir, ".lock")} {
		if _, err := os.Lstat(path); err != nil {
			return "State: not inspected (run Status after setup)"
		}
	}
	status, observationErr := m.Status()
	return p.menuStateFromStatus(status, observationErr)
}

// Use the same validated view as mode-overview; a requested mode, active
// Core process and independently verified VPN/Direct packet paths differ.
func (p operatorPresenter) menuStateFromStatus(status sc.Status, observationErr error) string {
	if status.Desired == "" {
		return "State: unverified (open Status for diagnostics)"
	}
	view, err := modeOverviewFromStatus(status, observationErr)
	if err != nil || view.DesiredMode == "" {
		return "State: unverified (open Status for diagnostics)"
	}
	requested := "Direct"
	switch view.DesiredMode {
	case "proxy_only":
		requested = "Proxy Only"
	case "smart_routing":
		requested = "Smart Routing (TUN)"
	}

	observed := "unverified (inspect Status)"
	switch {
	case view.ObservedMode == "smart_routing":
		observed = "native Core active (VPN path not independently verified)"
		switch view.StatusHealth {
		case "native_selected_path_degraded":
			observed = "native Core active; selected path degraded"
		case "native_selected_synthetic_qa_only":
			observed = "native Core active; synthetic QA health only"
		case "native_health_starting":
			observed = "native Core active; selected path starting"
		case "native_recovery_in_progress":
			observed = "native Core stopping; recovery in progress"
		}
	case view.ObservedMode == "proxy_only":
		observed = "Proxy Only service active (VPN path unverified)"
	case view.TrialPhase != "":
		observed = "experimental TUN " + view.TrialPhase + " (not general-host proof)"
	case view.DesiredMode == "smart_routing":
		observed = "native recovery unverified (inspect native-status)"
	case view.ProxyServiceState == "inactive" && observationErr == nil:
		observed = "Proxy Only service inactive (host route unverified)"
	}

	selected := "none"
	if view.SelectedProfileID != "" {
		selected = view.SelectedProfileID
	}
	return "Requested: " + requested + " | Observed: " + observed + " | Profile: " + selected
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
	case "apt_policy_conflict", "apt_untrusted_executable":
		return "Native APT executable or inherited policy could not be verified for the selected route.", "Inspect native APT settings locally; remove conflicting proxy, update or debug overrides before retrying 'server-connect apt'."
	case "proxy_unavailable":
		return "The local Proxy Only listener is not active; selected proxy routing is unverified.", "Inspect 'server-connect status' and connect a verified profile before retrying."
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

// These four common menu pages use task-oriented language. The equivalent
// command/--json APIs stay exact and complete for scripts and diagnostics.
// In particular an active process is never presented as proved VPN egress.
func operatorReadOnlyMenu(m *sc.Manager, command string, presenter operatorPresenter) (bool, int) {
	switch command {
	case "status", "mode-overview":
		status, observedErr := m.Status()
		if status.Desired == "" {
			if observedErr != nil {
				operatorPrintError(os.Stderr, observedErr)
			}
			return true, 1
		}
		view, viewErr := modeOverviewFromStatus(status, observedErr)
		if viewErr != nil {
			operatorPrintError(os.Stderr, viewErr)
			return true, 1
		}
		presenter.section("Connection status")
		for _, part := range strings.Split(presenter.menuStateFromStatus(status, observedErr), " | ") {
			presenter.printWrapped("  ", part)
		}
		presenter.printWrapped("  ", "Service health: "+view.StatusHealth)
		presenter.printWrapped("  ", "Selected VPN path proof: "+view.VPNPathProof)
		if command == "mode-overview" {
			presenter.section("Available modes")
			presenter.printWrapped("  ", "Direct: normal host networking")
			presenter.printWrapped("  ", "Proxy Only: explicit application proxy")
			presenter.printWrapped("  ", "Smart Routing: guarded TUN; activation requires host checks and fresh SSH confirmation")
			presenter.printWrapped("  ", "Smart host-wide permission is NOT automatically established by this overview")
			presenter.printWrapped("  ", "Host Direct path proof: "+view.HostDirectPathProof)
		}
		presenter.printWrapped("  ", "More details: sudo server-connect --json "+command)
		if observedErr != nil {
			operatorPrintError(os.Stderr, observedErr)
			return true, 1
		}
		return true, 0
	case "native-status":
		report, err := m.NativeStatus()
		presenter.section("Native guard and recovery")
		if report.Desired != "" {
			presenter.printWrapped("  ", "Requested: "+report.Desired)
		}
		if report.Observed != "" {
			presenter.printWrapped("  ", "Observed service: "+report.Observed)
		}
		presenter.printWrapped("  ", fmt.Sprintf("Recovery claim: %t; runtime guard verified: %t", report.RecoveryClaimPresent, report.GuardVerified))
		presenter.printWrapped("  ", "Selected VPN path proof: "+report.SelectedVPNPathProof)
		if report.HealthPhase != "" {
			presenter.printWrapped("  ", "Health: "+report.HealthPhase+" ("+report.HealthReason+")")
		}
		if report.ConfirmationState != "" {
			presenter.printWrapped("  ", fmt.Sprintf("SSH activation confirmation: %s (%d seconds remain)", report.ConfirmationState, report.ConfirmationSeconds))
		}
		presenter.printWrapped("  ", "More details: sudo server-connect --json native-status")
		if err != nil {
			operatorPrintError(os.Stderr, err)
			return true, 1
		}
		return true, 0
	case "profiles":
		profiles, err := m.List()
		if err != nil {
			operatorPrintError(os.Stderr, err)
			return true, 1
		}
		presenter.section("Saved profiles")
		if len(profiles) == 0 {
			presenter.printWrapped("  ", "None saved. Choose 3 Import to add your first VPN profile.")
		}
		for _, profile := range profiles {
			selected := ""
			if profile.Selected {
				selected = " [selected]"
			}
			presenter.printWrapped("  ", fmt.Sprintf("%q (ID %s)%s", profile.Name, profile.ID, selected))
		}
		presenter.printWrapped("  ", "Use the displayed ID for 4 Select or 8 Remove")
		return true, 0
	}
	return false, 0
}

func menuRun(m *sc.Manager, command ...string) int {
	if len(command) == 0 {
		return 1
	}
	ui := terminalPresenter(os.Stdout)
	fmt.Printf("\nRunning %s (reported results are scoped to this command):\n", command[0])
	if len(command) == 1 {
		if handled, code := operatorReadOnlyMenu(m, command[0], ui); handled {
			if code == 0 {
				fmt.Println(ui.tint("Completed:", "1;32") + " read-only inspection finished; this is not independent VPN path proof.")
			} else {
				fmt.Println(ui.tint("Not completed:", "1;31") + " the reported host state remains unverified.")
			}
			return code
		}
	}
	code := run(false, m, command)
	if code == 0 {
		fmt.Println(ui.tint("Completed:", "1;32") + " command succeeded. This is not independent VPN path proof.")
	} else {
		fmt.Println(ui.tint("Not completed:", "1;31") + " inspect the error and current state before retrying.")
	}
	return code
}
