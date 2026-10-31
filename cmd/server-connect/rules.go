package main

import (
	"flag"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/AChWorks/server-connect/internal/sc"
)

func routingOptionsError() error {
	return sc.Fault("invalid_arguments", "invalid routing rules operation or options")
}

// Refuse symlinks, FIFOs and devices *before* reading untrusted local list
// input, even when an administrator invokes the CLI as root. Stdin is an
// explicit streaming choice and has the same strict upper bound.
func readRoutingRuleList(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, int64(sc.MaxSmartRoutingImportBytes+1)))
		if err != nil || len(data) == 0 || len(data) > sc.MaxSmartRoutingImportBytes {
			return nil, sc.Fault("routing_rules_invalid", "local rule list exceeds the supported size or cannot be read")
		}
		return data, nil
	}
	if path == "" || strings.Contains(path, "://") {
		return nil, sc.Fault("routing_rules_invalid", "--file requires a local regular file or - for stdin")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, sc.Fault("routing_rules_unreadable", "local routing list cannot be opened (path withheld)")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > sc.MaxSmartRoutingImportBytes {
		return nil, sc.Fault("routing_rules_invalid", "routing list must be a bounded regular local file")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(sc.MaxSmartRoutingImportBytes+1)))
	if err != nil || len(data) != int(info.Size()) {
		return nil, sc.Fault("routing_rules_unreadable", "local routing list changed or could not be read")
	}
	return data, nil
}
func runSmartRoutingRules(jsonMode bool, m *sc.Manager, args []string) int {
	if len(args) == 0 {
		return output(jsonMode, nil, routingOptionsError())
	}
	action, args := args[0], args[1:]
	switch action {
	case "list":
		if len(args) != 0 {
			return output(jsonMode, nil, routingOptionsError())
		}
		value, err := m.InspectSmartRoutingRules()
		return output(jsonMode, value, err)
	case "add", "remove":
		opts := flag.NewFlagSet(action, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		cidr := opts.String("cidr", "", "canonical public IP/CIDR rule")
		domain := opts.String("domain", "", "canonical domain (VPN only)")
		suffix := opts.Bool("suffix", false, "domain matches apex and subdomains")
		via := opts.String("via", "", "direct|vpn; domain supports vpn only")
		if err := opts.Parse(args); err != nil || len(opts.Args()) != 0 || (*cidr == "") == (*domain == "") ||
			(*suffix && *cidr != "") || (action == "add" && *via == "") || (action == "remove" && *via != "") {
			return output(jsonMode, nil, routingOptionsError())
		}
		kind, value := "cidr", *cidr
		if *domain != "" {
			kind, value = "domain", *domain
			if *suffix {
				kind = "suffix"
			}
		}
		if action == "add" {
			report, err := m.AddSmartRoutingRule(sc.SmartRoutingRule{Type: kind, Value: value, Via: *via})
			return output(jsonMode, report, err)
		}
		report, err := m.RemoveSmartRoutingRule(kind, value)
		return output(jsonMode, report, err)
	case "preview":
		opts := flag.NewFlagSet(action, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		tunnel := opts.String("tunnel-if", "", "proposed TUN interface name")
		underlay := opts.String("underlay-if", "", "candidate underlay interface")
		tunnelIPv4 := opts.String("tunnel-ipv4", "", "private candidate TUN CIDR")
		tunnelIPv6 := opts.String("tunnel-ipv6", "", "optional private IPv6 candidate TUN CIDR")
		var domestic, protected, domesticIPv6, protectedIPv6 destinationFlags
		opts.Var(&domestic, "domestic-cidr", "explicit non-geographic IPv4 policy input")
		opts.Var(&protected, "protected-cidr", "explicit protected IPv4 host path")
		opts.Var(&domesticIPv6, "domestic-ipv6-cidr", "explicit IPv6 candidate policy input")
		opts.Var(&protectedIPv6, "protected-ipv6-cidr", "explicit protected IPv6 host path")
		if err := opts.Parse(args); err != nil || len(opts.Args()) != 0 || *tunnel == "" ||
			*underlay == "" || *tunnelIPv4 == "" || len(domestic) == 0 {
			return output(jsonMode, nil, routingOptionsError())
		}
		preview, err := m.PreviewSmartRoutingRules(sc.SmartTUNCandidateOptions{
			TunnelInterface: *tunnel, UnderlayInterface: *underlay,
			TunnelIPv4: *tunnelIPv4, TunnelIPv6: *tunnelIPv6,
			DomesticCIDRs: domestic, ProtectedCIDRs: protected,
			DomesticIPv6CIDRs: domesticIPv6, ProtectedIPv6CIDRs: protectedIPv6,
		})
		return output(jsonMode, preview, err)
	case "import":
		opts := flag.NewFlagSet(action, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		file := opts.String("file", "-", "local list file or -")
		source := opts.String("source", "", "stable source name")
		asOf := opts.String("as-of", "", "source metadata YYYY-MM-DD")
		digest := opts.String("sha256", "", "independently supplied exact file digest")
		replaces := opts.String("replaces-sha256", "", "expected previous source digest for atomic replacement")
		if err := opts.Parse(args); err != nil || len(opts.Args()) != 0 || *source == "" || *asOf == "" || *digest == "" {
			return output(jsonMode, nil, routingOptionsError())
		}
		raw, err := readRoutingRuleList(*file)
		if err != nil {
			return output(jsonMode, nil, err)
		}
		report, err := m.ImportSmartRoutingRules(*source, *asOf, *digest, *replaces, raw)
		return output(jsonMode, report, err)
	case "remove-source":
		opts := flag.NewFlagSet(action, flag.ContinueOnError)
		opts.SetOutput(io.Discard)
		source := opts.String("source", "", "source to remove")
		digest := opts.String("sha256", "", "exact expected digest of current imported source")
		if err := opts.Parse(args); err != nil || len(opts.Args()) != 0 || *source == "" || *digest == "" {
			return output(jsonMode, nil, routingOptionsError())
		}
		report, err := m.RemoveSmartRoutingSource(*source, *digest)
		return output(jsonMode, report, err)
	default:
		return output(jsonMode, nil, routingOptionsError())
	}
}
