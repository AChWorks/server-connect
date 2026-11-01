package sc

// This optional resolver integration is admitted ONLY in the separately
// authenticated Debian 13 QEMU test guest. It changes a manager-owned TUN
// link's DNS properties, never an existing uplink, global resolver, or file.
// Do not generalize this code without a separate host/ownership contract.
import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const nativeTUNVMResolvectlPath = "/usr/bin/resolvectl"
const nativeTUNVMResolverTimeout = 3 * time.Second

// Strictly parse one systemd-resolved link's bounded result. Unknown/multiple
// fields, another ifindex or interface name, and multiline presentation fail
// closed rather than becoming deletion or active-health authority.
func nativeTUNVMParseLinkResolver(raw []byte, index int, name string) (string, error) {
	if len(raw) == 0 || len(raw) > 512 || index < 2 || !smartTUNDeviceName.MatchString(name) {
		return "", nativeTUNUncertain("owned-link DNS observation unavailable")
	}
	s := strings.TrimSpace(string(raw))
	prefix := fmt.Sprintf("Link %d (%s):", index, name)
	if !strings.HasPrefix(s, prefix) {
		return "", nativeTUNUncertain("owned-link DNS identity changed")
	}
	value := strings.TrimSpace(strings.TrimPrefix(s, prefix))
	if strings.ContainsAny(value, " \r\n\t") || len(value) > 128 {
		return "", nativeTUNUncertain("owned-link DNS observation is ambiguous")
	}
	return value, nil
}

// Resolving a single link is read-only; all real mutation calls are bound to
// the same pinned activation-journal flock as the native ip/nft mutators.
// Neither PATH nor inherited proxy or loader variables may select a tool.
func nativeTUNVMResolverCommand(store *activationJournalDir, arguments ...string) ([]byte, error) {
	if err := verifyTrustedIPPath("/", nativeTUNVMResolvectlPath, 0); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeTUNVMResolverTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nativeTUNVMResolvectlPath, arguments...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = 200 * time.Millisecond
	var out bytes.Buffer
	if store == nil {
		cmd.Stdout = &out
	} else {
		cmd.Stdout = io.Discard
		if err := nativeTUNBindMutator(cmd, store); err != nil {
			return nil, err
		}
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return nil, nativeTUNUncertain("owned-link resolver command failed or outcome unknown")
	}
	if out.Len() > 512 {
		return nil, nativeTUNUncertain("owned-link resolver observation exceeds limit")
	}
	return out.Bytes(), nil
}

func nativeTUNVMReadLinkResolver(index int, name string) (string, string, error) {
	arg := strconv.Itoa(index)
	dns, err := nativeTUNVMResolverCommand(nil, "dns", arg)
	if err != nil {
		return "", "", err
	}
	domain, err := nativeTUNVMResolverCommand(nil, "domain", arg)
	if err != nil {
		return "", "", err
	}
	dnsText, err := nativeTUNVMParseLinkResolver(dns, index, name)
	if err != nil {
		return "", "", err
	}
	domainText, err := nativeTUNVMParseLinkResolver(domain, index, name)
	return dnsText, domainText, err
}

func nativeTUNVMResolverPreflight(o SmartTUNCandidateOptions) error {
	if o.DNSResolverIPv4 == "" {
		return nil
	}
	if !smartTUNVMPolicySupported(o) {
		return Fault("trial_unsupported", "VM-only DNS configuration is outside the admitted policy")
	}
	if err := smartTUNQAVMContext(); err != nil {
		return err
	}
	// This is the exact disposable QEMU user's known DHCP underlay. Refuse
	// changed or independently configured uplink DNS instead of rewriting it.
	dns, domain, err := nativeTUNVMReadLinkResolver(2, smartTUNVMUnderlay)
	if err != nil || dns != "10.0.2.3" || domain != "" {
		return Fault("trial_unsupported", "VM DNS underlay is not the supported disposable baseline")
	}
	return nil
}

func nativeTUNVMResolverDigest(record smartTUNTrialJournal) string {
	return sha256Hex([]byte(fmt.Sprintf("vm-link-dns-v1|%d|%s|%s|~.",
		record.Native.LinkIndex, record.TunnelInterface, record.Native.DNSResolverIPv4)))
}

func nativeTUNVMVerifyResolver(record smartTUNTrialJournal, active bool) error {
	n := record.Native
	if n == nil || n.DNSResolverIPv4 == "" {
		return nil
	}
	if err := nativeTUNCheckNamespace(record); err != nil {
		return err
	}
	link, err := nativeTUNObserveLink(record)
	if err != nil {
		return err
	}
	if !link.Present || !link.Persistent || link.Index != n.LinkIndex {
		return nativeTUNConflict("owned-link DNS interface is missing or changed")
	}
	if err := nativeTUNVerifyLink(record, link); err != nil {
		return err
	}
	dns, domain, err := nativeTUNVMReadLinkResolver(n.LinkIndex, record.TunnelInterface)
	if err != nil {
		return err
	}
	if active || n.DNSStage == "observed" {
		if dns != n.DNSResolverIPv4 || domain != "~." || n.DNSSHA256 != nativeTUNVMResolverDigest(record) {
			return nativeTUNConflict("owned-link DNS or routing domain differs from receipted state")
		}
		return nil
	}
	switch n.DNSStage {
	case "planned":
		if dns == "" && domain == "" {
			return nil
		}
	case "effect_possible":
		// Only our exact two setters can have run; a partial result is safe
		// to remove by deleting the exclusively owned interface. A foreign
		// address or domain never gains product cleanup authority.
		if (dns == "" || dns == n.DNSResolverIPv4) && (domain == "" || domain == "~.") {
			return nil
		}
	}
	return nativeTUNConflict("owned-link DNS has unreceipted or foreign configuration")
}

func nativeTUNVMApplyResolver(store *activationJournalDir, record *smartTUNTrialJournal, qaKillPoint string) error {
	if record.Native == nil || record.Native.DNSResolverIPv4 == "" {
		return nil
	}
	if record.Native.DNSStage != "planned" {
		return nativeTUNUncertain("owned-link DNS was already attempted")
	}
	if err := nativeTUNVMVerifyResolver(*record, false); err != nil {
		return err
	}
	next := cloneSmartTUNTrial(*record)
	next.Native.DNSStage = "effect_possible"
	if err := nativeTUNAdvance(store, record, next); err != nil {
		return err
	}
	index := strconv.Itoa(record.Native.LinkIndex)
	if _, err := nativeTUNVMResolverCommand(store, "dns", index, record.Native.DNSResolverIPv4); err != nil {
		return err
	}
	// A true process SIGKILL between the two DNS setters exercises the
	// durable effect_possible recovery path, not merely a mocked parser.
	if err := trialQAKillAt("after-native-dns-effect", qaKillPoint); err != nil {
		return err
	}
	if _, err := nativeTUNVMResolverCommand(store, "domain", index, "~."); err != nil {
		return err
	}
	dns, domain, err := nativeTUNVMReadLinkResolver(record.Native.LinkIndex, record.TunnelInterface)
	if err != nil {
		return err
	}
	if dns != record.Native.DNSResolverIPv4 || domain != "~." {
		return nativeTUNUncertain("owned-link DNS setter was not independently observed")
	}
	next = cloneSmartTUNTrial(*record)
	next.Native.DNSStage, next.Native.DNSSHA256 = "observed", nativeTUNVMResolverDigest(*record)
	return nativeTUNAdvance(store, record, next)
}
