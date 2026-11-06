//go:build linux

package sc

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// Run only as root inside a fresh, independently verified unshare --net.
// This is a real nftables/iptables/bridge kernel witness, not a host mutator
// or proof that an active generalized routing transaction is now safe.
func TestDockerNATRealKernelKnownShapeAndForeignDrift(t *testing.T) {
	if os.Getenv("SC_TEST_DOCKER_NAT_NATIVE") != "isolated-netns" {
		t.Skip("NOT_RUN: fresh root network namespace required")
	}
	_ = requireNativeQANetworkNamespace(t)
	if os.Geteuid() != 0 {
		t.Fatal("explicit isolated network namespace and root required")
	}
	run := func(command string, args ...string) {
		t.Helper()
		out, err := exec.Command(command, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("native disposable command failed: %s %v: %v (%s)", command, args, err, out)
		}
	}
	const ip, iptables = "/usr/sbin/ip", "/usr/sbin/iptables-nft"
	run(ip, "link", "add", "ens3", "type", "dummy")
	run(ip, "link", "set", "ens3", "up")
	run(ip, "link", "add", "docker0", "type", "bridge")
	run(ip, "address", "add", "172.17.0.1/16", "dev", "docker0")
	run(ip, "link", "set", "docker0", "up")
	run(iptables, "-t", "nat", "-N", "DOCKER")
	run(iptables, "-t", "nat", "-A", "PREROUTING", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER")
	run(iptables, "-t", "nat", "-A", "OUTPUT", "!", "-d", "127.0.0.0/8", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER")
	run(iptables, "-t", "nat", "-A", "POSTROUTING", "-s", "172.17.0.0/16", "!", "-o", "docker0", "-j", "MASQUERADE")
	run(iptables, "-t", "nat", "-A", "DOCKER", "-i", "docker0", "-j", "RETURN")
	observe := func() (bool, error) {
		raw, e := nativeTUNRunNFT(nil, nil, "-n", "-j", "-a", "list", "ruleset")
		if e != nil {
			return false, e
		}
		objects, e := nativeTUNNftObjects(raw)
		if e != nil {
			return false, e
		}
		return observeDockerNATShape(objects, "ens3"), nil
	}
	check := func(label string, want bool) {
		t.Helper()
		got, err := observe()
		if err != nil || got != want {
			t.Fatalf("%s: got=%v want=%v: %v", label, got, want, err)
		}
		fmt.Println(label + "=PASS")
	}
	check("DOCKER_NAT_REAL_KERNEL_BRIDGE_AND_OPAQUE_EXTENSIONS", true)
	// An additional Docker-published DNAT must never inherit the narrow
	// basic-bridge-only classifier without its own independently verified
	// ingress and host-local routing safety proof.
	run(iptables, "-t", "nat", "-A", "DOCKER", "-p", "tcp", "--dport", "18080", "-j", "DNAT", "--to-destination", "172.17.0.2:80")
	check("DOCKER_NAT_REAL_KERNEL_PUBLISHED_DNAT_REFUSED", false)
	run(iptables, "-t", "nat", "-D", "DOCKER", "-p", "tcp", "--dport", "18080", "-j", "DNAT", "--to-destination", "172.17.0.2:80")
	check("DOCKER_NAT_REAL_KERNEL_EXACT_DNAT_REMOVAL_REOBSERVED", true)
	run(ip, "address", "add", "10.66.0.1/24", "dev", "docker0")
	check("DOCKER_NAT_REAL_KERNEL_FOREIGN_BRIDGE_ADDRESS_REFUSED", false)
	run(ip, "address", "del", "10.66.0.1/24", "dev", "docker0")
	check("DOCKER_NAT_REAL_KERNEL_BRIDGE_IDENTITY_REOBSERVED", true)
}
