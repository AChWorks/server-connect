package sc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func nativeTUNConflict(message string) error  { return Fault("trial_resource_conflict", message) }
func nativeTUNUncertain(message string) error { return Fault("trial_recovery_uncertain", message) }

func nativeTUNNamespace() (uint64, uint64, error) {
	file, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return 0, 0, nativeTUNUncertain("network namespace unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, 0, nativeTUNUncertain("network namespace identity unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, nativeTUNUncertain("network namespace identity unsupported")
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func nativeTUNCheckNamespace(record smartTUNTrialJournal) error {
	d, i, err := nativeTUNNamespace()
	if err != nil {
		return err
	}
	if d != record.Native.NamespaceDev || i != record.Native.NamespaceIno {
		return nativeTUNConflict("native operation belongs to another network namespace")
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if boot != record.BootID {
		return nativeTUNConflict("old-boot kernel identities cannot authorize native deletion")
	}
	return nil
}

// A mutator inherits the SAME flock open-file-description. If this manager
// is SIGKILLed, its deferred LOCK_UN cannot run; recovery is excluded until
// the trusted child has exited, including any in-flight kernel operation.
// Pdeathsig accelerates termination but is not the quiescence proof. Normal
// Command.Run must always join before the parent explicitly releases lock.
func nativeTUNBindMutator(cmd *exec.Cmd, store *activationJournalDir) error {
	if store == nil || store.lock == nil {
		return nativeTUNUncertain("native mutator requires pinned operation lock")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	cmd.ExtraFiles = []*os.File{store.lock}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return nil
}

func nativeTUNRunIP(store *activationJournalDir, args ...string) error {
	if err := trustedHostIPExecutable(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), nativeIPCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nativeIPPath, args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = nativeIPPipeWaitDelay
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := nativeTUNBindMutator(cmd, store); err != nil {
		return err
	}
	if cmd.Run() != nil || ctx.Err() != nil {
		return nativeTUNUncertain("native ip operation outcome requires independent observation")
	}
	return nil
}

func nativeTUNRunNFT(store *activationJournalDir, input []byte, args ...string) ([]byte, error) {
	if err := verifyTrustedIPPath("/", nativeNFTPath, 0); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), firewallCommandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, nativeNFTPath, args...)
	cmd.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/bin:/bin"}
	cmd.Dir = "/"
	cmd.WaitDelay = firewallPipeWaitDelay
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
		if err := nativeTUNBindMutator(cmd, store); err != nil {
			return nil, err
		}
	}
	var output boundedFirewallOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, nativeTUNUncertain("native nft operation outcome requires independent observation")
	}
	return output.Bytes(), nil
}

func nativeTUNRows(args ...string) ([]map[string]json.RawMessage, error) {
	raw, err := nativeIPJSON(args...)
	if err != nil {
		return nil, err
	}
	return selectiveRows(raw)
}

func nativeTUNCanonical(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := canonicalJournalJSONStrict(raw)
	if err != nil {
		return "", err
	}
	return sha256Hex(canonical), nil
}

func nativeTUNRouteCanonical(row map[string]json.RawMessage) (string, error) {
	copyRow := make(map[string]json.RawMessage, len(row))
	for k, v := range row {
		copyRow[k] = v
	}
	if raw, ok := copyRow["flags"]; ok {
		var flags []string
		if json.Unmarshal(raw, &flags) != nil {
			return "", nativeTUNConflict("native route flags unsupported")
		}
		kept := []string{}
		for _, flag := range flags {
			if flag != "linkdown" {
				kept = append(kept, flag)
			}
		}
		sort.Strings(kept)
		copyRow["flags"], _ = json.Marshal(kept)
	}
	return nativeTUNCanonical(copyRow)
}

func nativeTUNLinkHash(row map[string]json.RawMessage) (string, bool, error) {
	rpf, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + selectiveText(row["ifname"]) + "/rp_filter")
	if err != nil {
		return "", false, nativeTUNUncertain("owned TUN reverse-path setting unavailable")
	}
	return nativeTUNLinkShape(row, strings.TrimSpace(string(rpf)))
}

func nativeTUNLinkShape(row map[string]json.RawMessage, rpFilter string) (string, bool, error) {
	raw, _ := json.Marshal(row)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if decoder.Decode(&object) != nil {
		return "", false, nativeTUNConflict("native link observation invalid")
	}
	linkInfo, ok := object["linkinfo"].(map[string]any)
	if !ok || linkInfo["info_kind"] != "tun" {
		return "", false, nativeTUNConflict("native link is not TUN")
	}
	data, ok := linkInfo["info_data"].(map[string]any)
	if !ok || data["type"] != "tun" {
		return "", false, nativeTUNConflict("native TUN detail unavailable")
	}
	persist, ok := data["persist"].(bool)
	if !ok {
		return "", false, nativeTUNConflict("native TUN persistence unavailable")
	}
	if multi, ok := data["multi_queue"].(bool); !ok || multi {
		return "", false, nativeTUNConflict("native TUN queue mode changed")
	}
	// Queue/carrier activity is the expected effect of attaching/stopping the
	// exact core. It does not authorize changes to other persistent attributes.
	delete(data, "persist")
	delete(data, "num_queues")
	delete(data, "num_disabled_queues")
	delete(object, "operstate")
	delete(object, "carrier")
	delete(object, "carrier_changes")
	delete(object, "carrier_up_count")
	delete(object, "carrier_down_count")
	if flags, ok := object["flags"].([]any); ok {
		kept := []string{}
		for _, v := range flags {
			s, ok := v.(string)
			if !ok {
				return "", false, nativeTUNConflict("native link flags unsupported")
			}
			if s != "LOWER_UP" && s != "RUNNING" && s != "NO-CARRIER" {
				kept = append(kept, s)
			}
		}
		sort.Strings(kept)
		object["flags"] = kept
	} else {
		return "", false, nativeTUNConflict("native link flags unavailable")
	}
	object["rp_filter"] = rpFilter
	hash, err := nativeTUNCanonical(object)
	return hash, persist, err
}

type nativeTUNLinkObservation struct {
	Present                                           bool
	Index                                             int
	Persistent                                        bool
	LinkSHA256, AddressSHA256, Dependent4, Dependent6 string
}

func nativeTUNObserveLink(record smartTUNTrialJournal) (nativeTUNLinkObservation, error) {
	n := record.Native
	rows, err := nativeTUNRows("-d", "-j", "link", "show")
	if err != nil {
		return nativeTUNLinkObservation{}, err
	}
	var selected map[string]json.RawMessage
	underlaySeen := false
	for _, row := range rows {
		index, ok := selectiveInt(row["ifindex"])
		if !ok {
			return nativeTUNLinkObservation{}, nativeTUNConflict("link index unavailable")
		}
		name := selectiveText(row["ifname"])
		if name == record.UnderlayInterface {
			if index != n.UnderlayIndex {
				return nativeTUNLinkObservation{}, nativeTUNConflict("native underlay generation changed")
			}
			underlaySeen = true
		}
		if name == record.TunnelInterface || (n.LinkIndex != 0 && index == n.LinkIndex) {
			if selected != nil || name != record.TunnelInterface || (n.LinkIndex != 0 && index != n.LinkIndex) {
				return nativeTUNLinkObservation{}, nativeTUNConflict("native TUN was renamed or replaced")
			}
			selected = row
		}
		if n.LinkIndex > 0 && index != n.LinkIndex {
			for _, key := range []string{"master", "link_index", "link"} {
				if ref, ok := selectiveInt(row[key]); ok && ref == n.LinkIndex {
					return nativeTUNLinkObservation{}, nativeTUNConflict("foreign link depends on native TUN")
				}
				if selectiveText(row[key]) == record.TunnelInterface {
					return nativeTUNLinkObservation{}, nativeTUNConflict("foreign link names native TUN as parent")
				}
			}
		}
	}
	if !underlaySeen {
		return nativeTUNLinkObservation{}, nativeTUNConflict("native underlay disappeared")
	}
	if selected == nil {
		return nativeTUNLinkObservation{}, nil
	}
	index, _ := selectiveInt(selected["ifindex"])
	if n.LinkIndex == 0 {
		return nativeTUNLinkObservation{Present: true, Index: index}, nil
	}
	if selectiveText(selected["ifalias"]) != "server-connect:"+record.OperationID {
		return nativeTUNLinkObservation{}, nativeTUNConflict("native TUN alias changed")
	}
	mtu, ok := selectiveInt(selected["mtu"])
	if !ok || mtu != 1400 {
		return nativeTUNLinkObservation{}, nativeTUNConflict("native TUN MTU changed")
	}
	hash, persistent, err := nativeTUNLinkHash(selected)
	if err != nil {
		return nativeTUNLinkObservation{}, err
	}
	addresses, err := nativeTUNRows("-j", "address", "show", "dev", record.TunnelInterface)
	if err != nil || len(addresses) != 1 {
		return nativeTUNLinkObservation{}, nativeTUNUncertain("complete native TUN addresses unavailable")
	}
	var info []json.RawMessage
	if json.Unmarshal(addresses[0]["addr_info"], &info) != nil {
		return nativeTUNLinkObservation{}, nativeTUNConflict("native address set unsupported")
	}
	if n.LinkStage == "create_possible" {
		if err := nativeTUNInitialAddresses(record, info); err != nil {
			return nativeTUNLinkObservation{}, err
		}
	}
	addressHash, err := nativeTUNCanonical(info)
	if err != nil {
		return nativeTUNLinkObservation{}, err
	}
	result := nativeTUNLinkObservation{Present: true, Index: index, Persistent: persistent, LinkSHA256: hash, AddressSHA256: addressHash}
	for _, family := range []int{4, 6} {
		routes, err := nativeTUNRows("-N", "-j", nativeFamilyFlag(family), "route", "show", "table", "all")
		if err != nil {
			return nativeTUNLinkObservation{}, err
		}
		dependencies := []string{}
		for _, route := range routes {
			// These forms require independent nexthop-object observation. This
			// bounded subtype must not miss a hidden interface dependency.
			if nativeTUNIndirectRoute(route) {
				return nativeTUNLinkObservation{}, nativeTUNConflict("indirect native route dependencies are unsupported")
			}
			table, err := selectiveTable(route["table"], true)
			if err != nil {
				return nativeTUNLinkObservation{}, err
			}
			if selectiveText(route["dev"]) == record.TunnelInterface {
				if table == nativeFamily(n, family).Table {
					continue
				}
				if n.LinkStage == "create_possible" && !nativeTUNInitialDependentRoute(record, family, route) {
					return nativeTUNLinkObservation{}, nativeTUNConflict("unexpected route appeared during exclusive TUN creation: " + nativeTUNRouteDiagnostic(family, route))
				}
				hash, err := nativeTUNRouteCanonical(route)
				if err != nil {
					return nativeTUNLinkObservation{}, err
				}
				dependencies = append(dependencies, hash)
			} else if address := nativeFamily(n, family).Address; address != "" && selectiveText(route["prefsrc"]) == netip.MustParsePrefix(address).Addr().String() {
				return nativeTUNLinkObservation{}, nativeTUNConflict("foreign route depends on native address")
			}
		}
		sort.Strings(dependencies)
		hash, err := nativeTUNCanonical(dependencies)
		if err != nil {
			return nativeTUNLinkObservation{}, err
		}
		if family == 4 {
			result.Dependent4 = hash
		} else {
			result.Dependent6 = hash
		}
	}
	return result, nil
}

func nativeTUNIndirectRoute(route map[string]json.RawMessage) bool {
	for _, key := range []string{"nhid", "nexthops", "multipath", "encap", "via"} {
		if _, present := route[key]; present {
			return true
		}
	}
	return false
}

func nativeTUNInitialAddresses(record smartTUNTrialJournal, rows []json.RawMessage) error {
	wanted := map[string]netip.Prefix{}
	for _, family := range []int{4, 6} {
		if raw := nativeFamily(record.Native, family).Address; raw != "" {
			prefix := netip.MustParsePrefix(raw)
			wanted[prefix.Addr().String()] = prefix
		}
	}
	if len(rows) != len(wanted) {
		return nativeTUNConflict("created TUN has an unexpected address set")
	}
	seen := map[string]bool{}
	for _, raw := range rows {
		var row map[string]json.RawMessage
		if json.Unmarshal(raw, &row) != nil {
			return nativeTUNConflict("created address observation invalid")
		}
		local := selectiveText(row["local"])
		prefix, ok := wanted[local]
		bits, bok := selectiveInt(row["prefixlen"])
		family := "inet"
		if prefix.IsValid() && prefix.Addr().Is6() {
			family = "inet6"
		}
		if !ok || seen[local] || !bok || bits != prefix.Bits() || selectiveText(row["family"]) != family || selectiveText(row["scope"]) != "global" {
			return nativeTUNConflict("created TUN address identity changed")
		}
		if _, exists := row["peer"]; exists {
			return nativeTUNConflict("unexpected TUN address peer")
		}
		if label := selectiveText(row["label"]); label != "" && label != record.TunnelInterface {
			return nativeTUNConflict("unexpected TUN address owner label")
		}
		seen[local] = true
	}
	return nil
}

// Only exact kernel local/broadcast/multicast routes may be captured as automatically
// dependent children of a newly created no-prefix-route TUN. A foreign route
// is never adopted merely because it appeared before the first receipt.
func nativeTUNInitialDependentRoute(record smartTUNTrialJournal, family int, row map[string]json.RawMessage) bool {
	table, err := selectiveTable(row["table"], true)
	protocol, ok := selectiveInt(row["protocol"])
	if err != nil || table != 255 || !ok || protocol != 2 || selectiveText(row["dev"]) != record.TunnelInterface {
		return false
	}
	typ, dst := nativeTUNRouteType(row["type"]), selectiveText(row["dst"])
	if family == 6 && typ == "multicast" && dst == "ff00::/8" {
		metric, ok := selectiveInt(row["metric"])
		return ok && metric == 256
	}
	if family == 4 && typ == "broadcast" {
		return nativeTUNInitialBroadcast(record, row)
	}
	f := nativeFamily(record.Native, family)
	if f.Address == "" || typ != "local" {
		return false
	}
	address := netip.MustParsePrefix(f.Address).Addr()
	if dst != address.String() && dst != netip.PrefixFrom(address, address.BitLen()).String() {
		return false
	}
	if source := selectiveText(row["prefsrc"]); source != "" && source != address.String() {
		return false
	}
	if raw, exists := row["metric"]; exists {
		metric, ok := selectiveInt(raw)
		if !ok || metric != 0 {
			return false
		}
	}
	return true
}

func nativeTUNInitialBroadcast(record smartTUNTrialJournal, row map[string]json.RawMessage) bool {
	// Linux v6.12 and v7.0 fib_add_ifaddr add the upper broadcast child
	// independently of IFA_F_NOPREFIXROUTE. fib_magic binds it to the
	// kernel protocol, local table, own source/device, link scope and metric0.
	// Accept only that computed child, never a generic broadcast route.
	prefix, err := netip.ParsePrefix(record.Native.IPv4.Address)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() >= 31 || prefix.Bits() == 0 {
		return false
	}
	network := prefix.Masked().Addr().As4()
	mask := ^uint32(0) << uint(32-prefix.Bits())
	var last [4]byte
	binary.BigEndian.PutUint32(last[:], binary.BigEndian.Uint32(network[:])|^mask)
	broadcast := netip.AddrFrom4(last)
	dst := selectiveText(row["dst"])
	if dst != broadcast.String() && dst != netip.PrefixFrom(broadcast, 32).String() {
		return false
	}
	if selectiveText(row["prefsrc"]) != prefix.Addr().String() {
		return false
	}
	scope, ok := selectiveInt(row["scope"])
	if (!ok || scope != 253) && selectiveText(row["scope"]) != "link" {
		return false
	}
	if raw, exists := row["metric"]; exists {
		metric, ok := selectiveInt(raw)
		if !ok || metric != 0 {
			return false
		}
	}
	for key := range row {
		switch key {
		case "type", "dst", "dev", "table", "protocol", "scope", "prefsrc", "metric", "flags":
		default:
			return false
		}
	}
	if raw, exists := row["flags"]; exists {
		var flags []string
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &flags) != nil {
			return false
		}
		for _, flag := range flags {
			if flag != "linkdown" {
				return false
			}
		}
	}
	return true
}

// Rejected rows need enough evidence for an isolated-host diagnosis, without
// dumping arbitrary nested fields, profile bytes, paths or credential URLs.
// The fixed projection accepts only bounded native identifiers/IPs/enums.
func nativeTUNRouteDiagnostic(family int, row map[string]json.RawMessage) string {
	result := map[string]any{"family": family}
	known := 0
	for _, key := range []string{"type", "table", "protocol", "scope", "metric"} {
		if raw, exists := row[key]; exists {
			known++
			if number, ok := selectiveInt(raw); ok {
				result[key] = number
				continue
			}
			value := selectiveText(raw)
			switch value {
			case "unicast", "local", "broadcast", "multicast", "unreachable", "kernel", "boot", "main", "default", "global", "link", "host", "nowhere":
				result[key] = value
			default:
				result[key] = "unsupported"
			}
		}
	}
	for _, key := range []string{"dst", "prefsrc", "gateway"} {
		if raw, exists := row[key]; exists {
			known++
			value := selectiveText(raw)
			address, addressErr := netip.ParseAddr(value)
			prefix, prefixErr := netip.ParsePrefix(value)
			switch {
			case key == "dst" && value == "default":
				result[key] = value
			case addressErr == nil && address.Zone() == "":
				result[key] = address.String()
			case prefixErr == nil:
				result[key] = prefix.String()
			default:
				result[key] = "unsupported"
			}
		}
	}
	if raw, exists := row["dev"]; exists {
		known++
		name := selectiveText(raw)
		if smartTUNDeviceName.MatchString(name) {
			result["dev"] = name
		} else {
			result["dev"] = "unsupported"
		}
	}
	if raw, exists := row["flags"]; exists {
		known++
		var flags []string
		valid := json.Unmarshal(raw, &flags) == nil && len(flags) <= 8 && !bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
		for _, flag := range flags {
			if flag != "linkdown" && flag != "onlink" && flag != "pervasive" && flag != "notify" {
				valid = false
			}
		}
		if valid {
			result["flags"] = flags
		} else {
			result["flags"] = "unsupported"
		}
	}
	if extra := len(row) - known; extra > 0 {
		result["extra_fields"] = extra
	}
	raw, _ := json.Marshal(result)
	return string(raw)
}

func nativeTUNVerifyLink(record smartTUNTrialJournal, observed nativeTUNLinkObservation) error {
	n := record.Native
	if !observed.Present {
		return nil
	}
	if n.LinkIndex == 0 || observed.Index != n.LinkIndex || observed.LinkSHA256 != n.LinkSHA256 || observed.AddressSHA256 != n.AddressSHA256 ||
		observed.Dependent4 != n.IPv4.DependentSHA256 || observed.Dependent6 != n.IPv6.DependentSHA256 {
		return nativeTUNConflict("native TUN identity, addresses or dependent routes changed")
	}
	if !observed.Persistent && n.LinkStage != "bound" && n.LinkStage != "persist_possible" {
		return nativeTUNConflict("native TUN lost persistence")
	}
	return nil
}

// The creation FD retains an ephemeral, exclusive device until its full
// identity/address/dependency receipt is durable. Only then may it persist.
func nativeTUNCreateEphemeral(store *activationJournalDir, record smartTUNTrialJournal) (*os.File, nativeTUNLinkObservation, error) {
	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nativeTUNLinkObservation{}, nativeTUNUncertain("cannot open TUN control device")
	}
	file := os.NewFile(uintptr(fd), "exclusive-native-tun")
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFCHR || stat.Rdev != uint64(10<<8|200) {
		_ = file.Close()
		return nil, nativeTUNLinkObservation{}, nativeTUNConflict("TUN control device identity is unsupported")
	}
	fail := func(err error) (*os.File, nativeTUNLinkObservation, error) {
		_ = file.Close()
		return nil, nativeTUNLinkObservation{}, err
	}
	var request [40]byte
	copy(request[:16], record.TunnelInterface)
	binary.NativeEndian.PutUint16(request[16:18], 0x0001|0x1000|0x8000|0x4000) // TUN, NO_PI, TUN_EXCL, VNET_HDR
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0x400454ca, uintptr(unsafe.Pointer(&request[0])))
	if errno != 0 {
		return fail(nativeTUNUncertain("exclusive TUN creation failed; existing links are never adopted"))
	}
	for _, args := range [][]string{{"link", "set", "dev", record.TunnelInterface, "mtu", "1400", "alias", "server-connect:" + record.OperationID}, {"link", "set", "dev", record.TunnelInterface, "addrgenmode", "none"}} {
		if err := nativeTUNRunIP(store, args...); err != nil {
			return fail(err)
		}
	}
	for _, family := range []int{4, 6} {
		f := nativeFamily(record.Native, family)
		if f.Address == "" {
			continue
		}
		args := []string{nativeFamilyFlag(family), "address", "add", f.Address, "dev", record.TunnelInterface, "noprefixroute"}
		if family == 6 {
			args = append(args, "nodad")
		}
		if err := nativeTUNRunIP(store, args...); err != nil {
			return fail(err)
		}
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/conf/"+record.TunnelInterface+"/rp_filter", []byte("2"), 0644); err != nil {
		return fail(nativeTUNUncertain("cannot configure owned TUN reverse-path filter"))
	}
	if err := nativeTUNRunIP(store, "link", "set", "dev", record.TunnelInterface, "up"); err != nil {
		return fail(err)
	}
	rows, err := nativeTUNRows("-d", "-j", "link", "show", "dev", record.TunnelInterface)
	if err != nil || len(rows) != 1 {
		return fail(nativeTUNUncertain("created TUN identity unavailable"))
	}
	index, ok := selectiveInt(rows[0]["ifindex"])
	if !ok || index < 2 {
		return fail(nativeTUNConflict("created TUN index invalid"))
	}
	copyRecord := cloneSmartTUNTrial(record)
	copyRecord.Native.LinkIndex = index
	observation, err := nativeTUNObserveLink(copyRecord)
	if err != nil {
		return fail(err)
	}
	if observation.Persistent {
		return fail(nativeTUNConflict("exclusive TUN unexpectedly became persistent"))
	}
	return file, observation, nil
}

func nativeTUNPersist(file *os.File) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), 0x400454cb, 1)
	if errno != 0 {
		return nativeTUNUncertain("TUN persistence result requires observation")
	}
	return nil
}

// A bounded construction-time watcher covers the official core's name-based
// attach. It is not a new service or a claim of attach-only ifindex support.
// Any lost event or observed generation change prevents a durable startup
// receipt; recovery must not erase that uncertainty from a later snapshot.
type nativeTUNLinkWatch struct{ fd int }

func nativeTUNWatchStart(record smartTUNTrialJournal) (*nativeTUNLinkWatch, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, nativeTUNUncertain("cannot watch native core attach")
	}
	w := &nativeTUNLinkWatch{fd: fd}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 256*1024); err != nil {
		w.close()
		return nil, nativeTUNUncertain("cannot bound native attach event buffer")
	}
	if err = syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Groups: 1}); err != nil {
		w.close()
		return nil, nativeTUNUncertain("cannot subscribe to native link events")
	}
	link, err := nativeTUNObserveLink(record)
	if err == nil && !link.Present {
		err = nativeTUNConflict("native TUN absent before core attach")
	}
	if err == nil {
		err = nativeTUNVerifyLink(record, link)
	}
	if err != nil {
		w.close()
		return nil, err
	}
	return w, nil
}

func (watch *nativeTUNLinkWatch) close() {
	if watch != nil && watch.fd >= 0 {
		_ = syscall.Close(watch.fd)
		watch.fd = -1
	}
}

func nativeTUNLinkEvents(messages []syscall.NetlinkMessage, record smartTUNTrialJournal) error {
	for _, message := range messages {
		if message.Header.Type == syscall.NLMSG_NOOP {
			continue
		}
		if message.Header.Type != syscall.RTM_NEWLINK && message.Header.Type != syscall.RTM_DELLINK {
			return nativeTUNUncertain("native attach events were lost or unsupported")
		}
		if len(message.Data) < syscall.SizeofIfInfomsg {
			return nativeTUNUncertain("native attach link event is truncated")
		}
		index := int(binary.NativeEndian.Uint32(message.Data[4:8]))
		attributes, err := syscall.ParseNetlinkRouteAttr(&message)
		if err != nil {
			return nativeTUNUncertain("native attach attributes are truncated")
		}
		name := ""
		for _, attribute := range attributes {
			if attribute.Attr.Type&0x3fff == syscall.IFLA_IFNAME {
				name = strings.TrimRight(string(attribute.Value), "\x00")
			}
		}
		relevant := index == record.Native.LinkIndex || index == record.Native.UnderlayIndex || name == record.TunnelInterface || name == record.UnderlayInterface
		if !relevant {
			continue
		}
		if message.Header.Type == syscall.RTM_DELLINK {
			return nativeTUNConflict("native attach observed a link generation deletion")
		}
		if (index == record.Native.LinkIndex && name != record.TunnelInterface) || (name == record.TunnelInterface && index != record.Native.LinkIndex) ||
			(index == record.Native.UnderlayIndex && name != record.UnderlayInterface) || (name == record.UnderlayInterface && index != record.Native.UnderlayIndex) {
			return nativeTUNConflict("native attach observed a rename or replacement")
		}
	}
	return nil
}

func (watch *nativeTUNLinkWatch) drain(record smartTUNTrialJournal) error {
	buffer := make([]byte, 64*1024)
	for batch := 0; batch < 128; batch++ {
		n, _, flags, from, err := syscall.Recvmsg(watch.fd, buffer, nil, syscall.MSG_DONTWAIT)
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			return nil
		}
		if err != nil || flags&syscall.MSG_TRUNC != 0 || n == 0 {
			return nativeTUNUncertain("native attach event stream lost data")
		}
		peer, ok := from.(*syscall.SockaddrNetlink)
		if !ok || peer.Pid != 0 {
			return nativeTUNUncertain("native attach event sender is untrusted")
		}
		messages, err := syscall.ParseNetlinkMessage(buffer[:n])
		if err != nil {
			return nativeTUNUncertain("native attach event framing invalid")
		}
		if err := nativeTUNLinkEvents(messages, record); err != nil {
			return err
		}
	}
	return nativeTUNUncertain("native attach event budget exceeded")
}

func (watch *nativeTUNLinkWatch) verify(record smartTUNTrialJournal) error {
	for attempt := 0; attempt < 12; attempt++ {
		if err := watch.drain(record); err != nil {
			return err
		}
		link, err := nativeTUNObserveLink(record)
		if err != nil {
			return err
		}
		if !link.Present {
			return nativeTUNConflict("native TUN disappeared during core attach")
		}
		if err := nativeTUNVerifyLink(record, link); err != nil {
			return err
		}
		rows, err := nativeTUNRows("-d", "-j", "link", "show", "dev", record.TunnelInterface)
		if err != nil || len(rows) != 1 {
			return nativeTUNUncertain("native attach queue identity unavailable")
		}
		index, ok := selectiveInt(rows[0]["ifindex"])
		if !ok || index != record.Native.LinkIndex {
			return nativeTUNConflict("native attach queue belongs to another interface")
		}
		var info struct {
			Data map[string]json.RawMessage `json:"info_data"`
		}
		if json.Unmarshal(rows[0]["linkinfo"], &info) != nil {
			return nativeTUNUncertain("native attach queue detail unavailable")
		}
		queues, qok := selectiveInt(info.Data["num_queues"])
		disabled, dok := selectiveInt(info.Data["num_disabled_queues"])
		if !qok || !dok || queues > 1 || disabled != 0 {
			return nativeTUNConflict("native attach queue ownership ambiguous")
		}
		if queues == 1 {
			return watch.drain(record)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nativeTUNUncertain("native core did not attach within bounded startup observation")
}

// RTM_DELLINK selects the already observed index, never a fresh name lookup.
// Rtnetlink has no compare-generation primitive for arbitrary link mutation;
// same-target privileged races remain outside this bounded fixture contract.
func nativeTUNDeleteLink(index int) error {
	if index < 2 {
		return nativeTUNConflict("invalid native TUN deletion index")
	}
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nativeTUNUncertain("cannot open native link deletion socket")
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nativeTUNUncertain("cannot bind native link deletion socket")
	}
	address, err := syscall.Getsockname(fd)
	if err != nil {
		return nativeTUNUncertain("native link deletion port unavailable")
	}
	local, ok := address.(*syscall.SockaddrNetlink)
	if !ok || local.Family != syscall.AF_NETLINK || local.Pid == 0 || local.Groups != 0 {
		return nativeTUNUncertain("native link deletion port invalid")
	}
	deadline := time.Now().Add(3 * time.Second)
	timeout := func(option int) error {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return syscall.ETIMEDOUT
		}
		value := syscall.NsecToTimeval(remaining.Nanoseconds())
		return syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, option, &value)
	}
	request := make([]byte, 32)
	binary.NativeEndian.PutUint32(request[0:4], 32)
	binary.NativeEndian.PutUint16(request[4:6], syscall.RTM_DELLINK)
	binary.NativeEndian.PutUint16(request[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	binary.NativeEndian.PutUint32(request[12:16], local.Pid)
	binary.NativeEndian.PutUint32(request[20:24], uint32(index))
	if err := timeout(syscall.SO_SNDTIMEO); err != nil {
		return nativeTUNUncertain("native link deletion deadline elapsed")
	}
	// Never repeat a possibly delivered mutation after EINTR or ACK loss.
	if err := syscall.Sendto(fd, request, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nativeTUNUncertain("native link deletion send outcome unknown")
	}
	buffer := make([]byte, 4096)
	for attempt := 0; attempt < 16; attempt++ {
		if err := timeout(syscall.SO_RCVTIMEO); err != nil {
			return nativeTUNUncertain("native link deletion deadline elapsed")
		}
		n, oob, flags, from, err := syscall.Recvmsg(fd, buffer, nil, 0)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return nativeTUNUncertain("native link deletion acknowledgement unavailable")
		}
		peer, ok := from.(*syscall.SockaddrNetlink)
		if !ok || peer.Family != syscall.AF_NETLINK || peer.Pid != 0 || peer.Groups != 0 || oob != 0 || n <= 0 || n > len(buffer) {
			return nativeTUNUncertain("native link acknowledgement sender or length invalid")
		}
		return nativeTUNDeleteACK(buffer[:n], flags, local.Pid, request)
	}
	return nativeTUNUncertain("native link deletion response budget exhausted")
}

func nativeTUNDeleteACK(data []byte, flags int, portID uint32, request []byte) error {
	bad := func() error {
		return nativeTUNUncertain("native link deletion acknowledgement is malformed or mismatched")
	}
	if len(request) != 32 || portID == 0 || len(data) < 36 || flags&(syscall.MSG_TRUNC|syscall.MSG_CTRUNC) != 0 {
		return bad()
	}
	length := int(binary.NativeEndian.Uint32(data[:4]))
	messageFlags := binary.NativeEndian.Uint16(data[6:8])
	if length != len(data) || length%4 != 0 || binary.NativeEndian.Uint16(data[4:6]) != syscall.NLMSG_ERROR || messageFlags & ^uint16(0x100) != 0 ||
		binary.NativeEndian.Uint32(data[8:12]) != binary.NativeEndian.Uint32(request[8:12]) || binary.NativeEndian.Uint32(data[12:16]) != portID ||
		!bytes.Equal(data[20:36], request[:16]) {
		return bad()
	}
	code := int32(binary.NativeEndian.Uint32(data[16:20]))
	if code > 0 || code < -4095 {
		return bad()
	}
	if code == 0 {
		if len(data) != 36 {
			return bad()
		}
		return nil
	}
	if messageFlags&0x100 != 0 {
		if len(data) != 36 {
			return bad()
		}
	} else if len(data) != 20+len(request) || !bytes.Equal(data[20:], request) {
		return bad()
	}
	return nativeTUNUncertain("native link deletion was rejected; independent observation required")
}

func nativeTUNNumber(raw json.RawMessage) (uint64, bool) {
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		n, e := strconv.ParseUint(number.String(), 0, 64)
		if e == nil {
			return n, true
		}
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		n, e := strconv.ParseUint(text, 0, 64)
		return n, e == nil
	}
	return 0, false
}

func nativeTUNRouteType(raw json.RawMessage) string {
	if value, ok := selectiveInt(raw); ok {
		switch value {
		case 1:
			return "unicast"
		case 2:
			return "local"
		case 3:
			return "broadcast"
		case 5:
			return "multicast"
		case 7:
			return "unreachable"
		}
	}
	return selectiveText(raw)
}

func nativeTUNRouteMatches(row map[string]json.RawMessage, record smartTUNTrialJournal, family int, kind string) bool {
	f := nativeFamily(record.Native, family)
	table, err := selectiveTable(row["table"], true)
	if err != nil || table != f.Table || !trialProtocolMatches(row["protocol"]) {
		return false
	}
	if kind == "rule" {
		priority, ok := selectiveInt(row["priority"])
		if !ok || priority != nativeTUNPriority {
			return false
		}
		mark, ok := nativeTUNNumber(row["fwmark"])
		if !ok || mark != uint64(nativeTUNCaptureMark) {
			return false
		}
		mask, ok := nativeTUNNumber(row["fwmask"])
		if !ok || mask != uint64(nativeTUNMarkMask) {
			return false
		}
		for key := range row {
			switch key {
			case "priority", "src", "table", "protocol", "fwmark", "fwmask":
			default:
				return false
			}
		}
		if source, present := row["src"]; present {
			return selectiveText(source) == "all"
		}
		return true
	}
	if selectiveText(row["dst"]) != "default" {
		return false
	}
	metric, ok := selectiveInt(row["metric"])
	if !ok {
		return false
	}
	if kind == "fallback" {
		if nativeTUNRouteType(row["type"]) != "unreachable" || metric != nativeTUNFallbackMetric {
			return false
		}
	} else {
		if typ := nativeTUNRouteType(row["type"]); typ != "" && typ != "unicast" {
			return false
		}
		if metric != nativeTUNMetric || selectiveText(row["dev"]) != record.TunnelInterface || selectiveText(row["prefsrc"]) != netip.MustParsePrefix(f.Address).Addr().String() {
			return false
		}
		// Linux IPv6 rt6_fill_node always reports RT_SCOPE_UNIVERSE,
		// including a device route requested with "scope link". IPv4
		// preserves RT_SCOPE_LINK. Do not mistake that family-specific
		// kernel representation for a foreign route or accept another scope.
		scope, present := row["scope"]
		if family == 6 {
			if present {
				number, ok := selectiveInt(scope)
				if (!ok || number != 0) && selectiveText(scope) != "global" {
					return false
				}
			}
		} else {
			number, ok := selectiveInt(scope)
			if (!ok || number != 253) && selectiveText(scope) != "link" {
				return false
			}
		}
	}
	for key := range row {
		switch key {
		case "type", "dst", "table", "protocol", "metric", "flags", "pref":
		case "dev", "scope", "prefsrc":
			if kind == "fallback" {
				return false
			}
		default:
			return false
		}
	}
	if pref, present := row["pref"]; present {
		number, ok := selectiveInt(pref)
		if (!ok || number != 0) && selectiveText(pref) != "medium" {
			return false
		}
	}
	var flags []string
	if raw, ok := row["flags"]; ok {
		if json.Unmarshal(raw, &flags) != nil {
			return false
		}
		for _, flag := range flags {
			if flag != "linkdown" {
				return false
			}
		}
	}
	return true
}

func nativeTUNObserveResource(record smartTUNTrialJournal, family int, kind string) (bool, string, error) {
	args := []string{"-N", "-j", nativeFamilyFlag(family), "route", "show", "table", "all"}
	if kind == "rule" {
		args = []string{"-N", "-j", nativeFamilyFlag(family), "rule", "show"}
	}
	rows, err := nativeTUNRows(args...)
	if err != nil {
		return false, "", err
	}
	return nativeTUNResourceRows(rows, record, family, kind)
}

func nativeTUNResourceRows(rows []map[string]json.RawMessage, record smartTUNTrialJournal, family int, kind string) (bool, string, error) {
	f := nativeFamily(record.Native, family)
	var selected map[string]json.RawMessage
	for _, row := range rows {
		if kind != "rule" && nativeTUNIndirectRoute(row) {
			return false, "", nativeTUNConflict("indirect route dependencies are unsupported")
		}
		table, err := selectiveTable(row["table"], true)
		if err != nil {
			return false, "", err
		}
		if kind == "rule" {
			if _, exists := row["goto"]; exists {
				return false, "", nativeTUNConflict("indirect policy-rule targets are unsupported")
			}
			priority, ok := selectiveInt(row["priority"])
			if !ok {
				return false, "", nativeTUNConflict("native rule priority unsupported")
			}
			for _, key := range []string{"iif", "oif"} {
				if selectiveText(row[key]) == record.TunnelInterface {
					return false, "", nativeTUNConflict("foreign interface-bound policy depends on native TUN")
				}
			}
			if priority != nativeTUNPriority {
				if table == f.Table {
					return false, "", nativeTUNConflict("foreign rule references native route table")
				}
				if _, present := row["fwmark"]; present {
					mask, ok := nativeTUNNumber(row["fwmask"])
					if !ok {
						mask = 0xffffffff
					}
					if mask&uint64(nativeTUNMarkMask) != 0 {
						return false, "", nativeTUNConflict("foreign policy overlaps reserved native mark field")
					}
				}
				continue
			}
			if !nativeTUNRouteMatches(row, record, family, kind) {
				return false, "", nativeTUNConflict("native rule slot contains a foreign selector")
			}
		} else {
			if table != f.Table {
				continue
			}
			candidate := "route"
			if nativeTUNRouteType(row["type"]) == "unreachable" {
				candidate = "fallback"
			}
			if f.Address == "" || !nativeTUNRouteMatches(row, record, family, candidate) {
				return false, "", nativeTUNConflict("native route table contains a foreign object")
			}
			if candidate != kind {
				continue
			}
		}
		if selected != nil {
			return false, "", nativeTUNConflict("native slot contains duplicate objects")
		}
		selected = row
	}
	if selected == nil {
		return false, "", nil
	}
	hash, err := nativeTUNRouteCanonical(selected)
	return true, hash, err
}

type nativeTUNNFTObservation struct {
	Present    bool
	Handle     uint64
	SHA256     string
	Generation uint32
	Matches    bool
	Count      int
	Objects    [24]smartTUNNativeNFTIdentity
}

func nativeTUNNftObjects(raw []byte) ([]map[string]any, error) {
	if _, err := decodeNFTSnapshot(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var top struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if decoder.Decode(&top) != nil {
		return nil, nativeTUNConflict("nft object envelope invalid")
	}
	return top.NFTables[1:], nil
}

func nativeNFTObjectHash(objects []map[string]any, stripHandles bool) (string, error) {
	raw, _ := json.Marshal(objects)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var copyObjects []map[string]any
	if decoder.Decode(&copyObjects) != nil {
		return "", nativeTUNConflict("nft object graph invalid")
	}
	for _, object := range copyObjects {
		for _, value := range object {
			fields, ok := value.(map[string]any)
			if !ok {
				return "", nativeTUNConflict("nft graph member invalid")
			}
			if stripHandles {
				delete(fields, "handle")
			}
		}
	}
	for _, object := range copyObjects {
		if !normalizeNftVolatile(object) {
			return "", nativeTUNConflict("nft graph counters invalid")
		}
		nativeNFTNormalizeEnums(object)
	}
	return nativeTUNCanonical(copyObjects)
}

// Numeric output pins meta oif/iif values to kernel ifindices, even after
// the link vanishes. Normalize only documented enum spelling differences;
// retain every expression, field, ordering and numeric value.
func nativeNFTNormalizeEnums(value any) {
	switch node := value.(type) {
	case []any:
		for _, child := range node {
			nativeNFTNormalizeEnums(child)
		}
	case map[string]any:
		if match, ok := node["match"].(map[string]any); ok {
			kind := ""
			if left, ok := match["left"].(map[string]any); ok {
				if meta, ok := left["meta"].(map[string]any); ok {
					kind, _ = meta["key"].(string)
				}
				if ct, ok := left["ct"].(map[string]any); ok && ct["key"] == "direction" {
					kind = "direction"
				}
				if p, ok := left["payload"].(map[string]any); ok && p["protocol"] == "icmpv6" && p["field"] == "type" {
					kind = "icmpv6-type"
				}
			}
			if kind != "" {
				match["right"] = nativeNFTEnumValue(kind, match["right"])
			}
		}
		for _, child := range node {
			nativeNFTNormalizeEnums(child)
		}
	}
}

func nativeNFTEnumValue(kind string, value any) any {
	if text, ok := value.(string); ok {
		sets := map[string]map[string]int{
			"nfproto":     {"ipv4": 2, "ipv6": 10},
			"l4proto":     {"tcp": 6, "udp": 17, "ipv6-icmp": 58},
			"direction":   {"original": 0, "reply": 1},
			"icmpv6-type": {"nd-router-solicit": 133, "nd-router-advert": 134, "nd-neighbor-solicit": 135, "nd-neighbor-advert": 136},
		}
		if number, exists := sets[kind][text]; exists {
			return json.Number(strconv.Itoa(number))
		}
	}
	if values, ok := value.([]any); ok {
		for i, v := range values {
			values[i] = nativeNFTEnumValue(kind, v)
		}
	}
	if fields, ok := value.(map[string]any); ok {
		if set, exists := fields["set"]; exists {
			fields["set"] = nativeNFTEnumValue(kind, set)
		}
	}
	return value
}

func nativeNFTIndices(value any, index int) (known, contains bool) {
	switch v := value.(type) {
	case json.Number:
		n, e := strconv.Atoi(v.String())
		return e == nil && n >= 0, e == nil && n == index && index > 0
	case []any:
		if len(v) == 0 {
			return false, false
		}
		for _, child := range v {
			k, c := nativeNFTIndices(child, index)
			if !k {
				return false, false
			}
			contains = contains || c
		}
		return true, contains
	case map[string]any:
		if len(v) == 1 {
			if set, ok := v["set"]; ok {
				return nativeNFTIndices(set, index)
			}
		}
	}
	return false, false
}

func nativeNFTMarkExpr(value any) bool {
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 1 {
		return false
	}
	for _, key := range []string{"meta", "ct"} {
		if expr, ok := fields[key].(map[string]any); ok && len(expr) == 1 && expr["key"] == "mark" {
			return true
		}
	}
	return false
}

func nativeNFTDisjointMarkRead(value map[string]any) bool {
	if len(value) != 1 {
		return false
	}
	parts, ok := value["&"].([]any)
	if !ok || len(parts) != 2 {
		return false
	}
	for side := 0; side < 2; side++ {
		if nativeNFTMarkExpr(parts[side]) {
			number, ok := parts[1-side].(json.Number)
			if !ok {
				return false
			}
			mask, err := strconv.ParseUint(number.String(), 10, 32)
			return err == nil && mask != 0 && uint32(mask)&nativeTUNMarkMask == 0
		}
	}
	return false
}

func nativeNFTInterfaceExpr(value any) string {
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 1 {
		return ""
	}
	meta, ok := fields["meta"].(map[string]any)
	if !ok || len(meta) != 1 {
		return ""
	}
	key, _ := meta["key"].(string)
	switch key {
	case "oif", "iif", "oifname", "iifname":
		return key
	}
	return ""
}

func nativeNFTForeignConflict(value any, record smartTUNTrialJournal) bool {
	switch v := value.(type) {
	case string:
		return v == record.TunnelInterface || strings.HasPrefix(v, "scnt_") || v == "172.31.99.1" || v == "fd73:99::1"
	case []any:
		for _, child := range v {
			if nativeNFTForeignConflict(child, record) {
				return true
			}
		}
	case map[string]any:
		// A literal masked read outside our field is provably disjoint.
		// Writers, whole-mark reads and indirect masks remain unsupported.
		if nativeNFTDisjointMarkRead(v) {
			return false
		}
		if meta, ok := v["meta"].(map[string]any); ok && meta["key"] == "mark" {
			return true
		}
		if ct, ok := v["ct"].(map[string]any); ok && ct["key"] == "mark" {
			return true
		}
		if match, ok := v["match"].(map[string]any); ok {
			for _, side := range []string{"left", "right"} {
				key := nativeNFTInterfaceExpr(match[side])
				if key == "" {
					continue
				}
				other := "right"
				if side == "right" {
					other = "left"
				}
				if key == "iif" || key == "oif" {
					known, contains := nativeNFTIndices(match[other], record.Native.LinkIndex)
					if !known || contains {
						return true
					}
				} else {
					text, ok := match[other].(string)
					if !ok || strings.HasPrefix(text, "@") || text == record.TunnelInterface {
						return true
					}
				}
				for name, child := range match {
					if name != side && nativeNFTForeignConflict(child, record) {
						return true
					}
				}
				return false
			}
		}
		// Interface maps/vmaps or named-set lookups not resolved above could
		// hide dependencies. Refuse them rather than guessing ownership.
		if nativeNFTInterfaceExpr(v) != "" {
			return true
		}
		for _, child := range v {
			if nativeNFTForeignConflict(child, record) {
				return true
			}
		}
	}
	return false
}

// The native fixture supports foreign observation/filtering, not another
// packet-path owner. A separate table or an unrelated mark is insufficient:
// late NAT, payload/metadata writes, queueing, duplication or offload could
// invalidate a decision already made by our OUTPUT guard. Keep this allowlist
// local to native admission/recovery; the legacy snapshot remains opaque.
func nativeNFTForeignRulePassive(fields map[string]any) bool {
	expressions, ok := fields["expr"].([]any)
	if !ok || len(expressions) == 0 {
		return false
	}
	for _, expression := range expressions {
		statement, ok := expression.(map[string]any)
		if !ok || len(statement) != 1 {
			return false
		}
		for kind, value := range statement {
			if !nativeNFTPassiveStatement(kind, value) {
				return false
			}
		}
	}
	return true
}

func nativeNFTPassiveStatement(kind string, value any) bool {
	text := func(v any) bool { s, ok := v.(string); return ok && s != "" && strings.TrimSpace(s) == s }
	fields, object := value.(map[string]any)
	switch kind {
	case "accept", "drop", "continue", "return":
		return value == nil
	case "jump", "goto":
		return object && len(fields) == 1 && text(fields["target"])
	case "match":
		if !object || len(fields) != 3 || fields["left"] == nil || fields["right"] == nil {
			return false
		}
		switch fields["op"] {
		case "==", "!=", "<", ">", "<=", ">=", "in":
			return true
		}
		return false
	case "counter":
		return text(value) || (object && len(fields) == 2 && validNftCounterValues(fields))
	case "reject":
		if !object {
			return false
		}
		for key, v := range fields {
			switch key {
			case "type":
				switch v {
				case "tcp reset", "icmpx", "icmp", "icmpv6":
				default:
					return false
				}
			case "expr":
				if !text(v) && !nativeNFTUnsignedScalar(v) {
					return false
				}
			default:
				return false
			}
		}
		return true
	case "log":
		if !object {
			return false
		}
		for key, v := range fields {
			switch key {
			case "prefix":
				if _, ok := v.(string); !ok {
					return false
				}
			case "group", "snaplen", "queue-threshold":
				if !nativeNFTUnsignedScalar(v) {
					return false
				}
			case "level":
				switch v {
				case "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug", "audit":
				default:
					return false
				}
			case "flags":
				flags, ok := v.([]any)
				if !ok {
					flags = []any{v}
				}
				for _, flag := range flags {
					switch flag {
					case "tcp sequence", "tcp options", "ip options", "skuid", "ether", "all":
					default:
						return false
					}
				}
			default:
				return false
			}
		}
		return true
	case "limit", "quota":
		if text(value) {
			return true
		}
		if !object {
			return false
		}
		required := "rate"
		if kind == "quota" {
			required = "val"
		}
		if !nativeNFTUnsignedScalar(fields[required]) {
			return false
		}
		for key, v := range fields {
			if key == "inv" {
				if _, ok := v.(bool); !ok {
					return false
				}
				continue
			}
			if kind == "limit" {
				switch key {
				case "rate", "burst":
					if !nativeNFTUnsignedScalar(v) {
						return false
					}
				case "rate_unit", "per", "burst_unit":
					if !text(v) {
						return false
					}
				default:
					return false
				}
			} else {
				switch key {
				case "val", "used":
					if !nativeNFTUnsignedScalar(v) {
						return false
					}
				case "val_unit", "used_unit":
					if !text(v) {
						return false
					}
				default:
					return false
				}
			}
		}
		return true
	default:
		// Includes NAT/redirect/tproxy, mangle, dup/fwd, queue, notrack,
		// conntrack assignment, flow/offload, verdict maps and future effects.
		return false
	}
}

func nativeNFTUnsignedScalar(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	_, err := strconv.ParseUint(number.String(), 10, 64)
	return err == nil
}

func nativeTUNNFTFromRows(objects []map[string]any, record smartTUNTrialJournal, generation uint32) (nativeTUNNFTObservation, error) {
	selected := []map[string]any{}
	var handle uint64
	for _, object := range objects {
		for kind, value := range object {
			fields := value.(map[string]any)
			owned := fields["family"] == "inet" && ((kind == "table" && fields["name"] == record.Native.NFTName) || (kind != "table" && fields["table"] == record.Native.NFTName))
			if owned {
				if kind == "table" {
					number, ok := fields["handle"].(json.Number)
					if !ok {
						return nativeTUNNFTObservation{}, nativeTUNConflict("nft table handle unavailable")
					}
					var err error
					handle, err = strconv.ParseUint(number.String(), 10, 64)
					if err != nil || handle == 0 {
						return nativeTUNNFTObservation{}, nativeTUNConflict("nft table handle invalid")
					}
				}
				selected = append(selected, object)
			} else {
				if kind == "flowtable" || (kind == "rule" && !nativeNFTForeignRulePassive(fields)) {
					return nativeTUNNFTObservation{}, nativeTUNConflict("foreign nft packet-path effects are unsupported by the native fixture")
				}
				if nativeNFTForeignConflict(fields, record) {
					return nativeTUNNFTObservation{}, nativeTUNConflict("foreign nft policy overlaps native mark or interface boundary")
				}
			}
		}
	}
	if len(selected) == 0 {
		return nativeTUNNFTObservation{Generation: generation}, nil
	}
	if handle == 0 {
		return nativeTUNNFTObservation{}, nativeTUNConflict("nft children exist without owned table identity")
	}
	if len(selected) > 24 {
		return nativeTUNNFTObservation{}, nativeTUNConflict("native nft graph contains extra objects")
	}
	var receipts [24]smartTUNNativeNFTIdentity
	for i, object := range selected {
		for kind, value := range object {
			fields := value.(map[string]any)
			number, ok := fields["handle"].(json.Number)
			if !ok {
				return nativeTUNNFTObservation{}, nativeTUNConflict("nft object handle unavailable")
			}
			h, err := strconv.ParseUint(number.String(), 10, 64)
			if err != nil || h == 0 {
				return nativeTUNNFTObservation{}, nativeTUNConflict("nft object handle invalid")
			}
			name, _ := fields["name"].(string)
			if kind == "rule" {
				name, _ = fields["chain"].(string)
			}
			semantic, err := nativeNFTObjectHash([]map[string]any{object}, true)
			if err != nil {
				return nativeTUNNFTObservation{}, err
			}
			receipts[i] = smartTUNNativeNFTIdentity{Kind: kind, Name: name, Handle: h, SHA256: semantic}
		}
	}
	hash, err := nativeNFTObjectHash(selected, false)
	if err != nil {
		return nativeTUNNFTObservation{}, err
	}
	semantic, err := nativeNFTObjectHash(selected, true)
	if err != nil {
		return nativeTUNNFTObservation{}, err
	}
	expected, err := nativeNFTObjectHash(nativeNFTObjects(record), true)
	if err != nil {
		return nativeTUNNFTObservation{}, err
	}
	return nativeTUNNFTObservation{Present: true, Handle: handle, SHA256: hash, Generation: generation, Matches: semantic == expected, Count: len(selected), Objects: receipts}, nil
}

func nativeTUNNFTReceiptCovers(record smartTUNTrialJournal, observed nativeTUNNFTObservation, complete bool) bool {
	n := record.Native
	if !observed.Present {
		return !complete
	}
	if n.NFTHandle == 0 || observed.Handle != n.NFTHandle || observed.Count > n.NFTCount {
		return false
	}
	if complete && (observed.Count != n.NFTCount || observed.SHA256 != n.NFT.SHA256) {
		return false
	}
	seen := map[smartTUNNativeNFTIdentity]bool{}
	last := -1
	for i := 0; i < observed.Count; i++ {
		object := observed.Objects[i]
		if seen[object] {
			return false
		}
		seen[object] = true
		found := false
		for j := last + 1; j < n.NFTCount; j++ {
			if object == n.NFTObjects[j] {
				found = true
				last = j
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Ownership of a surviving subset is distinct from containment. Removing
// capture is safe while this independently classified guard survives; losing
// a guard rule must never authorize a route/rule deletion that opens Direct.
func nativeTUNGuardIntact(record smartTUNTrialJournal, observed nativeTUNNFTObservation) bool {
	if !observed.Present || !nativeTUNNFTReceiptCovers(record, observed, false) {
		return false
	}
	last := -1
	for i := 0; i < record.Native.NFTCount; i++ {
		wanted := record.Native.NFTObjects[i]
		if wanted.Name != "guard" || (wanted.Kind != "chain" && wanted.Kind != "rule") {
			continue
		}
		found := false
		for j := last + 1; j < observed.Count; j++ {
			if wanted == observed.Objects[j] {
				found = true
				last = j
				break
			}
		}
		if !found {
			return false
		}
	}
	return last >= 0
}

func nativeTUNObserveNFT(record smartTUNTrialJournal) (nativeTUNNFTObservation, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before, err := nativeNFTGeneration()
		if err != nil {
			return nativeTUNNFTObservation{}, err
		}
		raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
		if err != nil {
			return nativeTUNNFTObservation{}, err
		}
		after, err := nativeNFTGeneration()
		if err != nil {
			return nativeTUNNFTObservation{}, err
		}
		if before == 0 || before != after {
			continue
		}
		objects, err := nativeTUNNftObjects(raw)
		if err != nil {
			return nativeTUNNFTObservation{}, err
		}
		return nativeTUNNFTFromRows(objects, record, after)
	}
	return nativeTUNNFTObservation{}, nativeTUNUncertain("nft generation changed during bounded ownership observation")
}
