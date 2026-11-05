//go:build linux

package sc

// Host ingress staging is a bounded prerequisite transaction, not Smart
// Routing activation. It never starts a core or changes FIB/RPDB/DNS. The
// existing independent recovery executor owns deadline and exact rollback.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
)

const hostIngressStageVersion = 5
const hostIngressStageIntent = "host_ingress_stage_v1"
const hostIngressSysctl = "/proc/sys/net/ipv4/tcp_fwmark_accept"

type hostIngressStage struct {
	Version       int    `json:"version"`
	Intent        string `json:"intent_type"`
	OperationID   string `json:"operation_id"`
	BootID        string `json:"boot_id"`
	NamespaceDev  uint64 `json:"namespace_dev"`
	NamespaceIno  uint64 `json:"namespace_ino"`
	Deadline      int64  `json:"deadline_uptime_sec"`
	Phase         string `json:"phase"`
	Underlay      string `json:"underlay"`
	UnderlayIndex int    `json:"underlay_index"`
	RawSHA256     string `json:"raw_sha256"`
	SysctlBefore  int    `json:"sysctl_before"`
	SysctlStage   string `json:"sysctl_stage"`
	NFTStage      string `json:"nft_stage"`
	NFTHandle     uint64 `json:"nft_handle"`
	NFTSHA256     string `json:"nft_sha256"`
}

type HostIngressStageReceipt struct {
	OperationID      string `json:"operation_id,omitempty"`
	Phase            string `json:"phase"`
	GuardScheduled   bool   `json:"guard_scheduled"`
	Drain            string `json:"drain"`
	RecoveryVerified bool   `json:"recovery_verified"`
	ActivationReady  bool   `json:"activation_ready"`
}

func hostIngressStageFields() map[string]bool {
	names := []string{"version", "intent_type", "operation_id", "boot_id", "namespace_dev", "namespace_ino", "deadline_uptime_sec", "phase", "underlay", "underlay_index", "raw_sha256", "sysctl_before", "sysctl_stage", "nft_stage", "nft_handle", "nft_sha256"}
	keys := map[string]bool{}
	for _, name := range names {
		keys[name] = true
	}
	return keys
}
func validateHostIngressStage(r hostIngressStage) error {
	if r.Version != hostIngressStageVersion || r.Intent != hostIngressStageIntent || !journalHex32.MatchString(r.OperationID) ||
		!trialBootIDPattern.MatchString(r.BootID) || r.NamespaceDev == 0 || r.NamespaceIno == 0 || r.Deadline <= 0 ||
		!smartTUNDeviceName.MatchString(r.Underlay) || r.Underlay == "lo" || r.UnderlayIndex < 2 ||
		!journalHex64.MatchString(r.RawSHA256) || (r.SysctlBefore != 0 && r.SysctlBefore != 1) {
		return activationJournalError("invalid host ingress staging identity")
	}
	if r.Phase != "pending" && r.Phase != "stop_requested" && r.Phase != "recovered" {
		return activationJournalError("invalid ingress transaction phase")
	}
	if r.SysctlStage != "planned" && r.SysctlStage != "effect_possible" && r.SysctlStage != "observed" && r.SysctlStage != "removed" {
		return activationJournalError("invalid ingress sysctl progress")
	}
	switch r.NFTStage {
	case "planned", "effect_possible":
		if r.NFTHandle != 0 || r.NFTSHA256 != "" {
			return activationJournalError("unacknowledged ingress table has a receipt")
		}
	case "observed", "remove_requested", "removed":
		if (r.NFTHandle == 0) != (r.NFTSHA256 == "") || (r.NFTSHA256 != "" && !journalHex64.MatchString(r.NFTSHA256)) ||
			(r.NFTStage != "removed" && r.NFTHandle == 0) {
			return activationJournalError("invalid ingress table receipt")
		}
	default:
		return activationJournalError("invalid ingress nft progress")
	}
	if (r.NFTStage == "effect_possible" || r.NFTStage == "observed" || r.NFTStage == "remove_requested") && r.SysctlStage != "observed" {
		return activationJournalError("ingress table progress precedes verified inheritance")
	}
	if r.SysctlStage == "removed" && r.NFTStage != "removed" {
		return activationJournalError("ingress sysctl cleanup precedes table removal")
	}
	if r.Phase == "recovered" && (r.SysctlStage != "removed" || r.NFTStage != "removed") {
		return activationJournalError("unrestored ingress transaction claims recovery")
	}
	if r.Phase == "pending" && (r.NFTStage == "remove_requested" || r.NFTStage == "removed" || r.SysctlStage == "removed") {
		return activationJournalError("pending ingress transaction has cleanup progress")
	}
	return nil
}
func decodeHostIngressStage(raw []byte) (hostIngressStage, error) {
	var r hostIngressStage
	if err := rejectAmbiguousJournalJSON(raw); err != nil {
		return r, err
	}
	if err := requireExactJournalKeys(raw, hostIngressStageFields()); err != nil {
		return r, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return r, activationJournalError("invalid ingress staging JSON")
	}
	for _, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return r, activationJournalError("null ingress staging field")
		}
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return r, activationJournalError("invalid ingress staging schema")
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return r, activationJournalError("trailing ingress staging data")
	}
	return r, validateHostIngressStage(r)
}
func loadHostIngressStage(store *activationJournalDir) (hostIngressStage, activationJournalFileIdentity, error) {
	raw, id, err := store.readJournal()
	if err != nil {
		return hostIngressStage{}, id, err
	}
	r, err := decodeHostIngressStage(raw)
	return r, id, err
}
func writeHostIngressStage(store *activationJournalDir, r hostIngressStage, old *activationJournalFileIdentity) error {
	if err := validateHostIngressStage(r); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return store.writeJournal(append(raw, '\n'), old)
}

// hostIngressPersist atomically records this stage in its enclosing operation
// journal while the manager lock is held. previous is nil only for creation;
// otherwise the callback must compare the complete old stage and enclosing
// operation identity before replacing the complete enclosing journal. It must
// not return success before durable storage. No callback may reacquire the lock.
type hostIngressPersist func(previous *hostIngressStage, next hostIngressStage) error

// The standalone v5 journal is retained for the bounded ingress prototype.
// General-host/native integration supplies its own enclosing-journal callback.
func hostIngressJournalPersist(store *activationJournalDir) hostIngressPersist {
	return func(previous *hostIngressStage, next hostIngressStage) error {
		if err := store.ensureLockIdentity(); err != nil {
			return err
		}
		if previous == nil {
			return writeHostIngressStage(store, next, nil)
		}
		observed, id, err := loadHostIngressStage(store)
		if err != nil {
			return err
		}
		if observed != *previous {
			return Fault("activation_journal_conflict", "host ingress operation changed while locked")
		}
		return writeHostIngressStage(store, next, &id)
	}
}

func persistHostIngressStage(persist hostIngressPersist, previous *hostIngressStage, next hostIngressStage) error {
	if persist == nil {
		return activationJournalError("ingress enclosing-journal persistence is required")
	}
	if err := validateHostIngressStage(next); err != nil {
		return err
	}
	if previous != nil {
		// Pass a copy: an unsuccessful callback cannot change the caller's
		// last durably acknowledged state through its comparison argument.
		old := *previous
		return persist(&old, next)
	}
	return persist(nil, next)
}
func advanceHostIngressStage(persist hostIngressPersist, current *hostIngressStage, next hostIngressStage) error {
	if current == nil {
		return activationJournalError("missing ingress progress record")
	}
	if err := persistHostIngressStage(persist, current, next); err != nil {
		return err
	}
	*current = next
	return nil
}
func readHostIngressSysctl() (int, error) {
	raw, err := readManagementProc(hostIngressSysctl, 16)
	if err != nil {
		return 0, ingressFault("tcp_fwmark_accept cannot be read")
	}
	if string(raw) == "0\n" {
		return 0, nil
	}
	if string(raw) == "1\n" {
		return 1, nil
	}
	return 0, ingressFault("tcp_fwmark_accept has an unsupported value")
}
func writeHostIngressSysctl(store *activationJournalDir, r hostIngressStage, value int) error {
	if value != 0 && value != 1 {
		return ingressFault("invalid ingress sysctl write")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if err := hostIngressNamespace(r); err != nil {
		return err
	}
	fd, err := syscall.Open(hostIngressSysctl, syscall.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ingressFault("tcp_fwmark_accept is not writable by the independent executor")
	}
	defer syscall.Close(fd)
	text := []byte(strconv.Itoa(value))
	n, err := syscall.Write(fd, text)
	if err != nil || n != len(text) {
		return ingressFault("tcp_fwmark_accept write outcome uncertain")
	}
	actual, err := readHostIngressSysctl()
	if err != nil || actual != value {
		return ingressFault("tcp_fwmark_accept write was not observed")
	}
	return nil
}
func hostIngressNamespace(r hostIngressStage) error {
	dev, ino, err := nativeTUNNamespace()
	if err != nil {
		return err
	}
	boot, err := trialBootIdentity()
	if err != nil {
		return err
	}
	if boot != r.BootID || dev != r.NamespaceDev || ino != r.NamespaceIno {
		return ingressFault("ingress staging boot or network namespace changed")
	}
	return nil
}
func hostIngressUnderlay(r hostIngressStage) error {
	device, err := net.InterfaceByName(r.Underlay)
	if err != nil || device.Index != r.UnderlayIndex {
		return ingressFault("ingress underlay interface generation changed")
	}
	return nil
}

// Both IPv4 and IPv6 backends are cross-checked. Native NOTRACK, custom
// chains, ranges, noncanonical ports, legacy owners and changed snapshots are
// refused. This inventory is a safety filter only, never an exemption.
func hostIngressRawSnapshot() (map[uint16]bool, string, error) {
	ports := map[uint16]bool{}
	var parts []string
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables"} {
		version, err := runReadOnlyHostNetfilter(binary, "-V")
		if err != nil || !bytes.Contains(version, []byte("(nf_tables)")) {
			return nil, "", ingressFault("both nft raw backends must be observable")
		}
		raw, err := runReadOnlyHostNetfilter(binary, "-t", "raw", "-S")
		if err != nil {
			return nil, "", err
		}
		p, err := strictHostIngressRawPorts(raw)
		if err != nil {
			return nil, "", err
		}
		for port := range p {
			ports[port] = true
		}
		legacy, err := runReadOnlyHostNetfilter(binary+"-legacy", "-t", "raw", "-S")
		if err != nil {
			return nil, "", ingressFault("legacy raw backend inventory unavailable")
		}
		if !strictEmptyLegacyRawPolicy(legacy) {
			return nil, "", ingressFault("legacy raw policy is not empty")
		}
		parts = append(parts, string(version), string(raw), string(legacy))
	}
	if len(ports) == 0 || len(ports) > 128 {
		return nil, "", ingressFault("stage requires a nonempty verified NOTRACK port inventory")
	}
	return ports, sha256Hex([]byte(strings.Join(parts, "\x00"))), nil
}

func hostIngressNFTObjects(r hostIngressStage) []map[string]any {
	// nft canonicalizes (mark & mask) | bits by setting ORed bits in the
	// AND mask too. Emit that same exact form before hashing ownership.
	name := "scin_" + r.OperationID
	meta := func(key string) any { return map[string]any{"meta": map[string]any{"key": key}} }
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	return []map[string]any{
		{"table": map[string]any{"family": "inet", "name": name, "comment": "server-connect:" + r.OperationID}},
		{"chain": map[string]any{"family": "inet", "table": name, "name": "ingress", "type": "filter", "hook": "prerouting", "prio": -310, "policy": "accept"}},
		{"rule": map[string]any{"family": "inet", "table": name, "chain": "ingress", "comment": "server-connect:" + r.OperationID, "expr": []any{
			match(meta("iifname"), r.Underlay),
			match(meta("l4proto"), "tcp"),
			match(map[string]any{"fib": map[string]any{"result": "type", "flags": []string{"daddr"}}}, 2), // RTN_LOCAL; nft -n renders the route type numerically
			match(map[string]any{"&": []any{meta("mark"), nativeTUNMarkMask}}, 0),
			map[string]any{"mangle": map[string]any{"key": meta("mark"), "value": map[string]any{"|": []any{map[string]any{"&": []any{meta("mark"), uint32(0xff00ffff) | nativeTUNBypassMark}}, nativeTUNBypassMark}}}},
		}}},
	}
}

type hostIngressNFTObservation struct {
	Present    bool
	Handle     uint64
	SHA256     string
	Generation uint32
	Matches    bool
}

func observeHostIngressNFT(r hostIngressStage) (hostIngressNFTObservation, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before, err := nativeNFTGeneration()
		if err != nil {
			return hostIngressNFTObservation{}, err
		}
		raw, err := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
		if err != nil {
			return hostIngressNFTObservation{}, err
		}
		after, err := nativeNFTGeneration()
		if err != nil {
			return hostIngressNFTObservation{}, err
		}
		if before == 0 || before != after {
			continue
		}
		objects, err := nativeTUNNftObjects(raw)
		if err != nil {
			return hostIngressNFTObservation{}, err
		}
		return hostIngressNFTFromRows(r, objects, after)
	}
	return hostIngressNFTObservation{}, ingressFault("nft staging observation changed repeatedly")
}
func hostIngressNFTFromRows(r hostIngressStage, objects []map[string]any, generation uint32) (hostIngressNFTObservation, error) {
	if generation == 0 || objects == nil {
		return hostIngressNFTObservation{}, ingressFault("ingress nft generation or object inventory absent")
	}
	var selected []map[string]any
	var handle uint64
	name := "scin_" + r.OperationID
	for _, item := range objects {
		if len(item) != 1 {
			return hostIngressNFTObservation{}, ingressFault("ambiguous ingress nft object")
		}
		for kind, raw := range item {
			fields, ok := raw.(map[string]any)
			if !ok {
				return hostIngressNFTObservation{}, ingressFault("malformed nft object")
			}
			if fields["family"] != "inet" || !((kind == "table" && fields["name"] == name) || (kind != "table" && fields["table"] == name)) {
				continue
			}
			if kind == "table" {
				n, ok := fields["handle"].(json.Number)
				if !ok {
					return hostIngressNFTObservation{}, ingressFault("missing ingress table handle")
				}
				var err error
				handle, err = strconv.ParseUint(n.String(), 10, 64)
				if err != nil || handle == 0 {
					return hostIngressNFTObservation{}, ingressFault("invalid ingress table handle")
				}
			}
			selected = append(selected, item)
		}
	}
	if len(selected) == 0 {
		return hostIngressNFTObservation{Generation: generation}, nil
	}
	if handle == 0 {
		return hostIngressNFTObservation{}, ingressFault("ingress children lack a table")
	}
	actual, err := nativeNFTObjectHash(selected, false)
	if err != nil {
		return hostIngressNFTObservation{}, err
	}
	semantic, err := nativeNFTObjectHash(selected, true)
	if err != nil {
		return hostIngressNFTObservation{}, err
	}
	expected, err := nativeNFTObjectHash(hostIngressNFTObjects(r), true)
	if err != nil {
		return hostIngressNFTObservation{}, err
	}
	return hostIngressNFTObservation{Present: true, Handle: handle, SHA256: actual, Generation: generation, Matches: semantic == expected}, nil
}

// The standalone prototype wrapper does not expose a public Apply API.
func applyHostIngressStageLocked(store *activationJournalDir, r *hostIngressStage, guard func() error) error {
	return applyHostIngressStageWithPersistLocked(store, r, guard, hostIngressJournalPersist(store))
}

// Must run under the manager lock AFTER independent prearm. The callback owns
// the sole enclosing activation journal. A failed write/effect retains recovery
// evidence and never authorizes capture. No tuple/source-port route is installed.
// General-host callers must require SysctlBefore == 1: Linux supplies no scalar
// generation/CAS ownership, so the 0->1 write path is isolated prototype QA only.
func applyHostIngressStageWithPersistLocked(store *activationJournalDir, r *hostIngressStage, guard func() error, persist hostIngressPersist) error {
	if persist == nil {
		return activationJournalError("ingress enclosing-journal persistence is required")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return err
	}
	if r == nil {
		return activationJournalError("missing ingress staging record")
	}
	if err := validateHostIngressStage(*r); err != nil {
		return err
	}
	if r.Phase != "pending" || r.SysctlStage != "planned" || r.NFTStage != "planned" {
		return activationJournalError("ingress Apply requires a fresh planned transaction")
	}
	if err := hostIngressBeforeDeadline(*r); err != nil {
		return err
	}
	if guard == nil {
		return Fault("guard_unavailable", "independent ingress recovery is required")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressNamespace(*r); err != nil {
		return err
	}
	if err := hostIngressUnderlay(*r); err != nil {
		return err
	}
	if err := hostIngressMarkBoundary(*r); err != nil {
		return err
	}
	_, rawHash, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	before, err := readHostIngressSysctl()
	if err != nil {
		return err
	}
	if rawHash != r.RawSHA256 || before != r.SysctlBefore {
		return ingressFault("ingress baseline changed before staging")
	}
	observed, err := observeHostIngressNFT(*r)
	if err != nil {
		return err
	}
	if observed.Present {
		return ingressFault("ingress operation table is occupied")
	}
	if err := persistHostIngressStage(persist, nil, *r); err != nil {
		return err
	}
	next := *r
	next.SysctlStage = "effect_possible"
	if err := advanceHostIngressStage(persist, r, next); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressBeforeDeadline(*r); err != nil {
		return err
	}
	if before == 0 {
		if err := writeHostIngressSysctl(store, *r, 1); err != nil {
			return err
		}
	}
	current, err := readHostIngressSysctl()
	if err != nil || current != 1 {
		return ingressFault("ingress inheritance changed before acknowledgement")
	}
	next = *r
	next.SysctlStage = "observed"
	if err := advanceHostIngressStage(persist, r, next); err != nil {
		return err
	}
	next = *r
	next.NFTStage = "effect_possible"
	if err := advanceHostIngressStage(persist, r, next); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressBeforeDeadline(*r); err != nil {
		return err
	}
	// All TCP packets to local destinations are marked. SYN-only marking
	// fails for SYN-cookie completion, which obtains its mark from final ACK.
	commands := make([]map[string]any, 0, 3)
	for i, object := range hostIngressNFTObjects(*r) {
		verb := "add"
		if i == 0 {
			verb = "create"
		}
		commands = append(commands, map[string]any{verb: object})
	}
	data, _ := json.Marshal(map[string]any{"nftables": commands})
	if _, err := nativeTUNRunNFT(store, data, "-j", "-f", "-"); err != nil {
		return err
	}
	observed, err = observeHostIngressNFT(*r)
	if err != nil {
		return err
	}
	if !observed.Present || !observed.Matches {
		return ingressFault("ingress creation was not independently observed")
	}
	next = *r
	next.NFTStage = "observed"
	next.NFTHandle = observed.Handle
	next.NFTSHA256 = observed.SHA256
	if err := advanceHostIngressStage(persist, r, next); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	return hostIngressStageIntact(*r)
}
func hostIngressStageIntact(r hostIngressStage) error {
	if err := validateHostIngressStage(r); err != nil {
		return err
	}
	if err := hostIngressBeforeDeadline(r); err != nil {
		return err
	}
	if r.Phase != "pending" || r.SysctlStage != "observed" || r.NFTStage != "observed" {
		return ingressFault("ingress staging is incomplete")
	}
	if err := hostIngressNamespace(r); err != nil {
		return err
	}
	if err := hostIngressUnderlay(r); err != nil {
		return err
	}
	if err := hostIngressMarkBoundary(r); err != nil {
		return err
	}
	_, hash, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	if hash != r.RawSHA256 {
		return ingressFault("foreign raw policy changed during staging")
	}
	value, err := readHostIngressSysctl()
	if err != nil || value != 1 {
		return ingressFault("ingress mark inheritance is unavailable")
	}
	observed, err := observeHostIngressNFT(r)
	if err != nil {
		return err
	}
	if !observed.Present || !observed.Matches || observed.Handle != r.NFTHandle || observed.SHA256 != r.NFTSHA256 {
		return ingressFault("ingress table ownership changed")
	}
	return hostIngressBeforeDeadline(r)
}

// This bounded two-sided snapshot does not establish packet quiescence or
// atomic socket absence. General-host capture additionally needs an independent
// kernel grace barrier and a kernel-filtered unsafe-socket absence proof.
func hostIngressDrainBarrier(r hostIngressStage, guard func() error) error {
	if guard == nil {
		return Fault("guard_unavailable", "independent ingress recovery is required")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressStageIntact(r); err != nil {
		return err
	}
	ports, hash, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	sockets, err := observeHostIngressSockets(ports)
	if err != nil {
		return err
	}
	if err := validateHostIngressDrain(sockets); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := hostIngressStageIntact(r); err != nil {
		return err
	}
	_, after, err := hostIngressRawSnapshot()
	if err != nil {
		return err
	}
	if hash != after || hash != r.RawSHA256 {
		return ingressFault("raw policy changed around ingress barrier")
	}
	return hostIngressBeforeDeadline(r)
}

func hostIngressBeforeDeadline(r hostIngressStage) error {
	uptime, err := trialUptime()
	if err != nil {
		return err
	}
	if uptime >= r.Deadline {
		return Fault("host_ingress_expired", "ingress staging deadline expired; capture remains refused")
	}
	return nil
}

// Only an acknowledged owned 0->1 effect may authorize a 1->0 restoration.
// Planned, unacknowledged, already removed or preexisting-1 values never
// acquire authority over a later foreign sysctl write. An observed value is not
// a Linux scalar generation/CAS: the mutating path remains isolated QA only.
func hostIngressRestoreSysctl(stage string, before, current int) (bool, error) {
	if (before != 0 && before != 1) || (current != 0 && current != 1) {
		return false, ingressFault("unverified ingress sysctl value")
	}
	switch stage {
	case "planned", "effect_possible", "observed", "removed":
	default:
		return false, activationJournalError("unknown ingress sysctl recovery stage")
	}
	if current == before {
		return false, nil
	}
	if stage == "observed" && before == 0 && current == 1 {
		return true, nil
	}
	return false, ingressFault("unowned or unacknowledged sysctl value retained")
}

func recoverHostIngressStageLocked(store *activationJournalDir, r *hostIngressStage, force bool) (HostIngressStageReceipt, error) {
	return recoverHostIngressStageWithPersistLocked(store, r, force, hostIngressJournalPersist(store))
}

func recoverHostIngressStageWithPersistLocked(store *activationJournalDir, r *hostIngressStage, force bool, persist hostIngressPersist) (HostIngressStageReceipt, error) {
	if persist == nil {
		return HostIngressStageReceipt{}, activationJournalError("ingress enclosing-journal persistence is required")
	}
	if err := store.ensureLockIdentity(); err != nil {
		return HostIngressStageReceipt{}, err
	}
	if r == nil {
		return HostIngressStageReceipt{}, activationJournalError("missing ingress recovery record")
	}
	if err := validateHostIngressStage(*r); err != nil {
		return HostIngressStageReceipt{}, err
	}
	receipt := HostIngressStageReceipt{OperationID: r.OperationID, Phase: r.Phase, Drain: "not_run"}
	boot, err := trialBootIdentity()
	if err != nil {
		return receipt, err
	}
	if boot != r.BootID {
		// No old kernel identity is reusable after boot, even if a table
		// happens to have the same name/handle. Only two-sided proof of
		// complete absence can acknowledge old-boot Off. In particular,
		// never restore a formerly 0 sysctl based on a prior-boot receipt.
		return recoverOldBootHostIngressLocked(r, persist)
	}
	if err := hostIngressNamespace(*r); err != nil {
		return receipt, err
	}
	now, err := trialUptime()
	if err != nil {
		return receipt, err
	}
	if !force && r.Phase == "pending" && now < r.Deadline && trialGuardScheduled() == nil && hostIngressStageIntact(*r) == nil {
		receipt.GuardScheduled = true
		return receipt, nil
	}
	if r.Phase != "recovered" {
		next := *r
		next.Phase = "stop_requested"
		if err := advanceHostIngressStage(persist, r, next); err != nil {
			return receipt, err
		}
		for attempts := 0; attempts < 3; attempts++ {
			observed, err := observeHostIngressNFT(*r)
			if err != nil {
				return receipt, err
			}
			if !observed.Present {
				next = *r
				next.NFTStage = "removed"
				if err := advanceHostIngressStage(persist, r, next); err != nil {
					return receipt, err
				}
				break
			}
			if (r.NFTStage != "observed" && r.NFTStage != "remove_requested") || !observed.Matches ||
				observed.Handle != r.NFTHandle || observed.SHA256 != r.NFTSHA256 {
				return receipt, ingressFault("unacknowledged, replaced or foreign ingress table retained")
			}
			next = *r
			next.NFTStage = "remove_requested"
			if err := advanceHostIngressStage(persist, r, next); err != nil {
				return receipt, err
			}
			err = nativeNFTDeleteTableCAS(observed.Handle, observed.Generation)
			if errors.Is(err, errNativeNFTGenerationChanged) {
				continue
			}
			if err != nil {
				return receipt, err
			}
			after, err := observeHostIngressNFT(*r)
			if err != nil {
				return receipt, err
			}
			if after.Present {
				return receipt, ingressFault("ingress table still present after deletion")
			}
			next = *r
			next.NFTStage = "removed"
			if err := advanceHostIngressStage(persist, r, next); err != nil {
				return receipt, err
			}
			break
		}
		if r.NFTStage != "removed" {
			return receipt, ingressFault("ingress rollback exceeded nft generation retry bound")
		}
		current, err := readHostIngressSysctl()
		if err != nil {
			return receipt, err
		}
		restore, err := hostIngressRestoreSysctl(r.SysctlStage, r.SysctlBefore, current)
		if err != nil {
			return receipt, err
		}
		if restore {
			if err := writeHostIngressSysctl(store, *r, r.SysctlBefore); err != nil {
				return receipt, err
			}
		}

		next = *r
		next.SysctlStage = "removed"
		next.Phase = "recovered"
		if err := advanceHostIngressStage(persist, r, next); err != nil {
			return receipt, err
		}
	}
	observed, err := observeHostIngressNFT(*r)
	if err != nil {
		return receipt, err
	}
	value, err := readHostIngressSysctl()
	if err != nil {
		return receipt, err
	}
	if observed.Present || value != r.SysctlBefore {
		return receipt, ingressFault("ingress baseline restoration not verified")
	}
	receipt.Phase, receipt.RecoveryVerified = "recovered", true
	return receipt, nil
}

// recoverOldBootHostIngressLocked never mutates Linux networking. A prior
// boot's nft table handle, namespace inode, and scalar sysctl write receipt
// cannot authorize deletion or sysctl restoration on the current boot.
// Only a previously enabled tcp_fwmark_accept=1 is safe to acknowledge;
// if the earlier operation enabled it from 0, retain uncertainty instead.
// The caller already holds the exact enclosing journal lock.
func recoverOldBootHostIngressLocked(r *hostIngressStage, persist hostIngressPersist) (HostIngressStageReceipt, error) {
	receipt := HostIngressStageReceipt{OperationID: r.OperationID, Phase: r.Phase, Drain: "not_run"}
	if persist == nil {
		return receipt, activationJournalError("old-boot ingress recovery requires enclosing persistence")
	}
	if r.SysctlBefore != 1 {
		return receipt, ingressFault("old-boot sysctl ownership cannot be restored or attributed")
	}
	absent := func() error {
		value, err := readHostIngressSysctl()
		if err != nil {
			return err
		}
		if value != 1 {
			return ingressFault("old-boot ingress sysctl baseline changed")
		}
		observed, err := observeHostIngressNFT(*r)
		if err != nil {
			return err
		}
		if observed.Present {
			return ingressFault("old-boot ingress table name is occupied; prior handles cannot delete it")
		}
		return nil
	}
	// Never modify or acknowledge an old-boot record on a single snapshot.
	if err := absent(); err != nil {
		return receipt, err
	}
	if r.Phase == "pending" {
		next := *r
		next.Phase = "stop_requested"
		if err := advanceHostIngressStage(persist, r, next); err != nil {
			return receipt, err
		}
	}
	if err := absent(); err != nil {
		return receipt, err
	}
	if r.Phase != "recovered" {
		next := *r
		next.NFTStage = "removed"
		next.SysctlStage = "removed"
		next.Phase = "recovered"
		if err := advanceHostIngressStage(persist, r, next); err != nil {
			return receipt, err
		}
	}
	// A competing foreign table or sysctl change after the fsynced journal
	// can still be detected. No ownership was transferred by this receipt.
	if err := absent(); err != nil {
		return receipt, err
	}
	receipt.Phase, receipt.RecoveryVerified = "recovered", true
	return receipt, nil
}

// Public activation deliberately remains unavailable: the stage is not a
// complete host-routing guard. These primitives are exercised in independent
// disposable namespaces before they can be integrated into general-host Apply.
func newHostIngressStage(underlay string, deadlineSeconds int) (hostIngressStage, error) {
	var r hostIngressStage
	if deadlineSeconds < 4 || deadlineSeconds > 600 || !smartTUNDeviceName.MatchString(underlay) || underlay == "lo" {
		return r, Fault("invalid_arguments", "ingress staging requires one underlay and a 4-600 second deadline")
	}
	device, err := net.InterfaceByName(underlay)
	if err != nil || device.Index < 2 {
		return r, ingressFault("ingress underlay unavailable")
	}
	r = hostIngressStage{Version: hostIngressStageVersion, Intent: hostIngressStageIntent, Underlay: underlay, UnderlayIndex: device.Index, Phase: "pending", SysctlStage: "planned", NFTStage: "planned"}
	r.OperationID, err = randomHex(16)
	if err != nil {
		return r, err
	}
	r.BootID, err = trialBootIdentity()
	if err != nil {
		return r, err
	}
	r.NamespaceDev, r.NamespaceIno, err = nativeTUNNamespace()
	if err != nil {
		return r, err
	}
	now, err := trialUptime()
	if err != nil {
		return r, err
	}
	r.Deadline = now + int64(deadlineSeconds)
	r.SysctlBefore, err = readHostIngressSysctl()
	if err != nil {
		return r, err
	}
	_, r.RawSHA256, err = hostIngressRawSnapshot()
	if err != nil {
		return r, err
	}
	return r, validateHostIngressStage(r)
}
