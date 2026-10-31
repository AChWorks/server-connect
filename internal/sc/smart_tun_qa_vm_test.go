package sc

import (
	"testing"
)

func qaVMPolicyFixture() SmartTUNCandidateOptions {
	return SmartTUNCandidateOptions{
		TunnelInterface:   smartTUNVMInterface,
		UnderlayInterface: smartTUNVMUnderlay,
		TunnelIPv4:        "172.31.99.1/30",
		ProtectedCIDRs:    []string{"10.0.2.2/32"},
		DomesticCIDRs:     []string{"5.22.0.10/32"},
		Exceptions:        []SmartTUNCIDRException{{CIDR: "1.1.1.1/32", Via: "direct"}},
	}
}

func TestSmartTUNQAVMAdmissionPolicyBoundaries(t *testing.T) {
	fixture := qaVMPolicyFixture()
	if !smartTUNVMPolicySupported(fixture) {
		t.Fatal("exact VM non-Docker policy rejected")
	}
	if smartTUNTrialFixturePolicySupported(fixture) {
		t.Fatal("new VM lane accidentally adopted legacy Docker identity")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SmartTUNCandidateOptions)
	}{
		{"underlay", func(x *SmartTUNCandidateOptions) { x.UnderlayInterface = "eth0" }},
		{"tunnel", func(x *SmartTUNCandidateOptions) { x.TunnelInterface = "tun0" }},
		{"protected", func(x *SmartTUNCandidateOptions) { x.ProtectedCIDRs = []string{"0.0.0.0/0"} }},
		{"real-vpn-witness-direct", func(x *SmartTUNCandidateOptions) {
			x.Exceptions = []SmartTUNCIDRException{{CIDR: "1.0.0.1/32", Via: "direct"}}
		}},
		{"real-vpn-witness-vpn-exception", func(x *SmartTUNCandidateOptions) {
			x.Exceptions = []SmartTUNCIDRException{{CIDR: "1.0.0.0/24", Via: "vpn"}}
		}},
		{"dns-domain-direct", func(x *SmartTUNCandidateOptions) {
			x.DomainExceptions = []SmartTUNDomainException{{Domain: "example.com", Via: "direct"}}
		}},
		{"dual-stack-unproven", func(x *SmartTUNCandidateOptions) { x.TunnelIPv6 = "fd73:99::1/64" }},
		{"too-many", func(x *SmartTUNCandidateOptions) {
			for i := 0; i < 9; i++ {
				x.Exceptions = append(x.Exceptions, SmartTUNCIDRException{CIDR: "9.9.9.9/32", Via: "vpn"})
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := qaVMPolicyFixture()
			tc.mutate(&policy)
			if smartTUNVMPolicySupported(policy) {
				t.Fatal("unapproved VM policy passed")
			}
		})
	}
	if err := smartTUNNativeCandidateContext(fixture, "10.254.72.2"); err == nil {
		t.Fatal("mixed peer/topology admitted")
	}
	if err := smartTUNQAVMContext(); err == nil {
		t.Fatal("development environment is not the exact isolated QEMU guest")
	}
}

func TestSmartTUNQAVMHealthWireEvidence(t *testing.T) {
	good := smartTUNHealthNotRunEvidence()
	good.ProbeCount = 2
	good.UnderlayHealthy = true
	good.VPNHealthy = true
	good.IPv4TCP = true
	good.IPv4HTTPS = true
	good.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
	good.Reason = "vm_https_only_udp_dns_not_run"
	if !validSmartTUNQAVMHealthEvidence(good) {
		t.Fatal("bounded, truthful VM evidence refused")
	}
	if validSmartTUNHTTPSEvidence(good, false) {
		t.Fatal("VM-only evidence misclassified as full protocol proof")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SmartTUNHealthEvidence)
	}{
		{"claims-udp", func(e *SmartTUNHealthEvidence) { e.IPv4UDP = true }},
		{"claims-dns", func(e *SmartTUNHealthEvidence) { e.IPv4DNS = true }},
		{"claims-ipv6", func(e *SmartTUNHealthEvidence) { e.IPv6TCP = true }},
		{"missing-https", func(e *SmartTUNHealthEvidence) { e.HTTPSResults[0] = SmartTUNHTTPSResult{Result: "not_run"} }},
		{"forged-extra-target", func(e *SmartTUNHealthEvidence) {
			e.HTTPSResults[1] = SmartTUNHTTPSResult{Result: "pass", StatusCode: 200}
		}},
		{"failed-underlay", func(e *SmartTUNHealthEvidence) { e.UnderlayHealthy = false }},
		{"failed-vpn", func(e *SmartTUNHealthEvidence) { e.VPNHealthy = false }},
		{"bad-count", func(e *SmartTUNHealthEvidence) { e.ProbeCount = 17 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sample := good
			tc.mutate(&sample)
			if validSmartTUNQAVMHealthEvidence(sample) {
				t.Fatal("false VPN health evidence accepted")
			}
		})
	}
}
