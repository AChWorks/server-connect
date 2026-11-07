# Native route and rule ownership counterexample

This opt-in diagnostic exercises a known release blocker. Its product assertion
is that a separately created replacement survives Server Connect cleanup. If
cleanup deletes the replacement, the test **fails**. A completed reproduction
must never be reported as successful product ownership acceptance.

## Execution

Use an authorized disposable Linux test host with root, Go, iproute2, nftables,
iptables-nft, a working TUN device and network-namespace support. Build the test
executable as an ordinary user, inspect its source and hash, then run the exact
binary as root:

```sh
go test -c -o /tmp/sc-native-ownership-tests ./internal/sc
sha256sum /tmp/sc-native-ownership-tests
sudo env SC_TEST_NATIVE_OWNERSHIP_ABA=isolated-netns \
  /tmp/sc-native-ownership-tests \
  -test.run='^TestNativeOwnershipABAPreservesForeignReplacement$' \
  -test.v -test.timeout=180s
```

The top-level test only reads the initial network namespace. Every mutating case
is launched through `unshare --net`; the child independently verifies namespace
separation and a loopback-only initial interface inventory before setup. It
reuses the v9 kernel fixture, including its task-owned Docker/NOTRACK examples,
an actual native TUN and guard, and the real fsynced enclosing journal. Core
service state is simulated; this is not an installed-service or outbound test.
Namespace destruction disposes of only these synthetic resources.

The normal source suite skips both diagnostic entry points. A skip does not
satisfy this ownership requirement. Do not add an expected-failure wrapper,
invert the preservation assertion or treat the helper's successful replacement
as acceptance of recovery.

## What the four cases observe

For both the IPv4 RPDB rule and the TUN route:

1. Install actual kernel policy and read back its durable observed receipt.
2. Ask a separate subprocess to delete the original, independently witness
   absence, then create an identical new object.
3. Compare independent normalized `ip -N -j` output and the product's receipt
   hash before and after replacement.
4. Execute the real single-resource cleanup with the real enclosing-parent
   persistence callback and an independently observed intact guard.
5. Require the foreign replacement to survive. Compare disjoint concurrent
   owner fixtures and the initial host's route/rule/nft structure as well.

The second timing performs step 2 inside the existing guard-observer callback,
after cleanup's last route/rule observation but before its deletion command.
No new production hook or altered recovery semantics is involved. Logs
distinguish setup failures from a completed ownership-invariant failure.

The fixture's separate writer is synthetic and explicitly authorized. It models
an overlapping privileged reconciler, not an unidentified real host owner.
Noncolliding foreign resources have a separate preservation check. The test
does not imply that ordinary Docker bridge updates themselves recreate these
specific reserved RPDB/FIB tuples.

## Interpretation and limits

A hash of observable attributes is not a non-reusable kernel object generation.
The current record can prove that the manager once acknowledged a matching
object; it cannot, by itself, prove uninterrupted lifetime until deletion.
Adding a nonce to the journal, protocol, priority or table number does not make
the kernel deletion conditional on that lifetime.

The primary kernel API documentation describes route and FIB-rule deletion
through their selectable attributes:

- [Route netlink operations](https://www.kernel.org/doc/html/v6.13/networking/netlink_spec/rt_route.html)
- [FIB rule netlink operations](https://docs.kernel.org/6.15/networking/netlink_spec/rt_rule.html)
- [nftables operations and generation attributes](https://docs.kernel.org/netlink/specs/nftables.html)

The nftables generation-conditioned deletion mechanism is a different primitive
and does not supply a generation condition for a subsequent RPDB/FIB deletion.

The existing canonical safety contract already excludes unobservable identical
replacement by an arbitrary privileged writer from the isolated fixture's proof.
That exclusion must not silently become general-host admission or a claim that
observable overlapping resources are safe to erase. Supported independent
network managers must retain their resources. Product admission must establish
the supported ownership boundary; a cooperative reservation is an explicit
operational contract, not authentication supplied by a route number.

This diagnostic does not decide that contract, authorize adoption of
unreceipted objects, change the P0 recovery requirement, prove IPv6, or establish
a public release. Exact executions, failures, kernel versions and artifact
hashes belong in the owning PR evidence.
