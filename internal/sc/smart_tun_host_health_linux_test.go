//go:build linux

package sc

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func hostHealthPlanFixture(ipv6 bool) HostHealthPlan {
	p := HostHealthPlan{Round: 1, OperationID: strings.Repeat("a", 32), BootID: "11111111-2222-3333-4444-555555555555", ConfigSHA256: strings.Repeat("b", 64),
		TunnelInterface: "schost0", UnderlayInterface: "eth0", EndpointIP: "45.67.89.10", EndpointPort: 443,
		IPv4: HostHealthFamilyPlan{Enabled: true, UnderlaySource: "10.20.0.2", DNSResolver: "1.0.0.1",
			Trace:            HostHealthTraceTarget{Address: "1.1.1.1", Port: 443, ServerName: "one.one.one.one", Path: "/cdn-cgi/trace"},
			ExpectedDirectIP: "8.8.8.8", ExpectedVPNIP: "9.9.9.9"},
		Domestic: HostHealthTraceTarget{Address: "185.143.233.133", Port: 443, ServerName: "example.com", Path: "/cdn-cgi/trace"}}
	if ipv6 {
		p.IPv6 = HostHealthFamilyPlan{Enabled: true, UnderlaySource: "fd73:99::2", DNSResolver: "2606:4700:4700::1001",
			Trace:            HostHealthTraceTarget{Address: "2606:4700:4700::1111", Port: 443, ServerName: "one.one.one.one", Path: "/cdn-cgi/trace"},
			ExpectedDirectIP: "2001:4860:4860::8888", ExpectedVPNIP: "2606:4700:8::9"}
	}
	return p
}
func TestHostHealthPlanRequiresExplicitFamiliesIdentityAndTLSPaths(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		if err := ValidateHostHealthPlan(hostHealthPlanFixture(ipv6)); err != nil {
			t.Fatal(err)
		}
	}
	for name, change := range map[string]func(*HostHealthPlan){
		"operation":                   func(p *HostHealthPlan) { p.OperationID = "bad" },
		"boot":                        func(p *HostHealthPlan) { p.BootID = "bad" },
		"config":                      func(p *HostHealthPlan) { p.ConfigSHA256 = "" },
		"same device":                 func(p *HostHealthPlan) { p.TunnelInterface = p.UnderlayInterface },
		"loopback device":             func(p *HostHealthPlan) { p.UnderlayInterface = "lo" },
		"device syntax":               func(p *HostHealthPlan) { p.TunnelInterface = "wrong;name" },
		"no IPv4":                     func(p *HostHealthPlan) { p.IPv4.Enabled = false },
		"missing VPN identity":        func(p *HostHealthPlan) { p.IPv4.ExpectedVPNIP = "" },
		"same egress":                 func(p *HostHealthPlan) { p.IPv4.ExpectedVPNIP = p.IPv4.ExpectedDirectIP },
		"private egress":              func(p *HostHealthPlan) { p.IPv4.ExpectedVPNIP = "10.0.0.1" },
		"mapped egress":               func(p *HostHealthPlan) { p.IPv4.ExpectedVPNIP = "::ffff:9.9.9.9" },
		"reserved trace":              func(p *HostHealthPlan) { p.IPv4.Trace.Address = "192.0.2.1" },
		"resolver hostname":           func(p *HostHealthPlan) { p.IPv4.DNSResolver = "example.com" },
		"private resolver":            func(p *HostHealthPlan) { p.IPv4.DNSResolver = "192.168.0.1" },
		"trace hostname":              func(p *HostHealthPlan) { p.IPv4.Trace.Address = "one.one.one.one" },
		"TLS identity":                func(p *HostHealthPlan) { p.IPv4.Trace.ServerName = "ONE.ONE.ONE.ONE" },
		"header injection":            func(p *HostHealthPlan) { p.IPv4.Trace.ServerName = "a.example\r\nX: y" },
		"path injection":              func(p *HostHealthPlan) { p.IPv4.Trace.Path = "/trace\r\n" },
		"caller query":                func(p *HostHealthPlan) { p.IPv4.Trace.Path = "/trace?token=a" },
		"scheme path":                 func(p *HostHealthPlan) { p.IPv4.Trace.Path = "//example.com/trace" },
		"zero port":                   func(p *HostHealthPlan) { p.EndpointPort = 0 },
		"endpoint hostname":           func(p *HostHealthPlan) { p.EndpointIP = "vpn.example.com" },
		"endpoint family":             func(p *HostHealthPlan) { p.EndpointIP = "2606:4700::1" },
		"source family":               func(p *HostHealthPlan) { p.IPv4.UnderlaySource = "fd73::1" },
		"source zone":                 func(p *HostHealthPlan) { p.IPv4.UnderlaySource = "1.2.3.4%eth0" },
		"disabled family data":        func(p *HostHealthPlan) { p.IPv6.ExpectedVPNIP = "2606:4700::1" },
		"unprotected domestic family": func(p *HostHealthPlan) { p.Domestic.Address = "2606:4700::1" },
	} {
		t.Run(name, func(t *testing.T) {
			p := hostHealthPlanFixture(false)
			change(&p)
			if ValidateHostHealthPlan(p) == nil {
				t.Fatal("invalid activation-grade plan accepted")
			}
		})
	}
	p := hostHealthPlanFixture(true)
	p.EndpointIP = "2606:4700::1"
	if err := ValidateHostHealthPlan(p); err != nil {
		t.Fatal(err)
	}
}
func TestHostHealthPlanBindsSelectedAndUnderlaySocketsWithoutAmbientRouting(t *testing.T) {
	p := hostHealthPlanFixture(true)
	probes := hostHealthProbes(p)
	if len(probes) != 8 {
		t.Fatalf("unexpected probe count: %d", len(probes))
	}
	for _, probe := range probes {
		switch probe.role {
		case "selected", "dns":
			if probe.device != p.TunnelInterface || probe.bypass || probe.source != "" {
				t.Fatalf("selected path accidentally bypassed: %+v", probe)
			}
		case "direct", "endpoint", "domestic":
			source := p.IPv4.UnderlaySource
			if probe.family == 6 {
				source = p.IPv6.UnderlaySource
			}
			if probe.device != p.UnderlayInterface || !probe.bypass || probe.source != source {
				t.Fatalf("underlay path not bound: %+v", probe)
			}
		default:
			t.Fatalf("unexpected role: %+v", probe)
		}
	}
}
func hostHealthPassingProbe(_ context.Context, p hostHealthProbe) HostHealthResult {
	r := HostHealthResult{Result: "pass"}
	if p.role != "dns" && p.role != "endpoint" {
		r.HTTPStatus = 200
		r.ObservedIP = p.expected
	}
	return r
}
func TestHostHealthEvidenceRequiresEveryEnabledProtocolAndPreservesMismatch(t *testing.T) {
	p := hostHealthPlanFixture(true)
	e := runHostHealth(context.Background(), p, hostHealthPassingProbe)
	if !e.Healthy || e.Reason != "healthy" || !e.IPv4.EgressVerified || !e.IPv6.EgressVerified || !e.DomesticVerified || e.ProbeCount != 8 ||
		e.IPv4.DNS != "pass" || e.IPv6.UDP != "pass" || e.OperationID != p.OperationID || e.ConfigSHA256 != p.ConfigSHA256 ||
		!journalHex64.MatchString(e.PlanSHA256) {
		t.Fatalf("incomplete round accepted: %+v", e)
	}
	other := p
	other.EndpointPort++
	changed := runHostHealth(context.Background(), other, hostHealthPassingProbe)
	if changed.PlanSHA256 == e.PlanSHA256 {
		t.Fatal("changed plan reused evidence digest")
	}
	for _, role := range []string{"selected", "direct", "dns", "endpoint", "domestic"} {
		for _, family := range []int{4, 6} {
			if role == "endpoint" && family == 6 || role == "domestic" && family == 6 {
				continue
			}
			got := runHostHealth(context.Background(), p, func(ctx context.Context, probe hostHealthProbe) HostHealthResult {
				if probe.role == role && probe.family == family {
					return HostHealthResult{Result: "timeout"}
				}
				return hostHealthPassingProbe(ctx, probe)
			})
			if got.Healthy {
				t.Fatalf("failed %s IPv%d ignored: %+v", role, family, got)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := runHostHealth(ctx, p, func(ctx context.Context, probe hostHealthProbe) HostHealthResult {
		if probe.role == "selected" && probe.family == 4 {
			cancel()
			return HostHealthResult{Result: "path_mismatch", HTTPStatus: 200, ObservedIP: p.IPv4.ExpectedDirectIP}
		}
		<-ctx.Done()
		return HostHealthResult{Result: "canceled"}
	})
	if got.Healthy || got.Reason != "path_mismatch" || got.IPv4.SelectedHTTPS.ObservedIP != p.IPv4.ExpectedDirectIP {
		t.Fatalf("critical evidence erased by cancellation: %+v", got)
	}
}
func TestHostHealthDisabledFamilyAndUnrequestedDomesticAreNeverReportedAsPass(t *testing.T) {
	p := hostHealthPlanFixture(false)
	p.Domestic = HostHealthTraceTarget{}
	e := runHostHealth(context.Background(), p, hostHealthPassingProbe)
	if !e.Healthy || e.IPv6.Enabled || e.IPv6.TCP != "not_run" || e.IPv6.DNS != "not_run" || e.IPv6.EgressVerified ||
		e.DomesticVerified || e.DomesticHTTPS.Result != "not_run" || e.ProbeCount != 4 {
		t.Fatalf("unmeasured coverage promoted: %+v", e)
	}
}
func TestHostHealthCanceledAndInvalidPlansStartNoProbesAndJoinWorkers(t *testing.T) {
	p := hostHealthPlanFixture(false)
	var active atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := runHostHealth(ctx, p, func(context.Context, hostHealthProbe) HostHealthResult {
		t.Error("canceled round probed")
		return HostHealthResult{}
	})
	if e.Healthy || e.ProbeCount != 0 || e.Reason != "round_canceled" {
		t.Fatalf("%+v", e)
	}
	p.OperationID = "invalid"
	e = runHostHealth(context.Background(), p, func(context.Context, hostHealthProbe) HostHealthResult {
		t.Error("invalid plan probed")
		return HostHealthResult{}
	})
	if e.Reason != "invalid_plan" || e.Healthy {
		t.Fatalf("%+v", e)
	}
	p = hostHealthPlanFixture(false)
	ctx, cancel = context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	e = runHostHealth(ctx, p, func(ctx context.Context, _ hostHealthProbe) HostHealthResult {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		return HostHealthResult{Result: "canceled"}
	})
	if e.Healthy || e.Reason != "round_canceled" || active.Load() != 0 || e.ProbeCount != 5 {
		t.Fatalf("workers not joined: %+v active=%d", e, active.Load())
	}
}

func TestHostHealthIPv6VPNCanBeMeasuredWithoutInventingDirectIPv6(t *testing.T) {
	p := hostHealthPlanFixture(true)
	p.IPv6.DirectUnavailable = true
	p.IPv6.UnderlaySource = ""
	p.IPv6.ExpectedDirectIP = ""
	if err := ValidateHostHealthPlan(p); err != nil {
		t.Fatal(err)
	}
	e := runHostHealth(context.Background(), p, hostHealthPassingProbe)
	if !e.Healthy || !e.IPv6.EgressVerified || e.IPv6.DirectVerified || !e.IPv6.DirectUnavailable ||
		e.IPv6.DirectHTTPS.Result != "unavailable" || e.ProbeCount != 7 {
		t.Fatalf("incorrect IPv6 coverage: %+v", e)
	}
	for name, change := range map[string]func(*HostHealthPlan){
		"IPv4 unavailable": func(p *HostHealthPlan) {
			p.IPv4.DirectUnavailable = true
			p.IPv4.UnderlaySource = ""
			p.IPv4.ExpectedDirectIP = ""
		},
		"ignored IPv6 source":    func(p *HostHealthPlan) { p.IPv6.UnderlaySource = "fd73::1" },
		"ignored IPv6 Direct":    func(p *HostHealthPlan) { p.IPv6.ExpectedDirectIP = "2001:4860::8888" },
		"missing IPv6 VPN":       func(p *HostHealthPlan) { p.IPv6.ExpectedVPNIP = "" },
		"IPv6 endpoint underlay": func(p *HostHealthPlan) { p.EndpointIP = "2606:4700::1" },
		"IPv6 domestic underlay": func(p *HostHealthPlan) { p.Domestic.Address = "2606:4700::1" },
		"missing round":          func(p *HostHealthPlan) { p.Round = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			change(&bad)
			if ValidateHostHealthPlan(bad) == nil {
				t.Fatal("contradictory scope accepted")
			}
		})
	}
}

func TestHostHealthEvidenceValidationRejectsStaleRoundsAndFabricatedCoverage(t *testing.T) {
	p := hostHealthPlanFixture(false)
	e := runHostHealth(context.Background(), p, hostHealthPassingProbe)
	if err := ValidateHostHealthEvidence(p, e); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*HostHealthEvidence){
		"round":              func(e *HostHealthEvidence) { e.Round++ },
		"plan":               func(e *HostHealthEvidence) { e.PlanSHA256 = strings.Repeat("c", 64) },
		"boot":               func(e *HostHealthEvidence) { e.BootID = "00000000-2222-3333-4444-555555555555" },
		"source":             func(e *HostHealthEvidence) { e.IPv4.SelectedHTTPS.ObservedIP = "8.8.8.8" },
		"unmeasured UDP":     func(e *HostHealthEvidence) { e.IPv4.UDP = "not_run" },
		"missing DNS":        func(e *HostHealthEvidence) { e.IPv4.DNS = "not_run" },
		"invented IPv6":      func(e *HostHealthEvidence) { e.IPv6.TCP = "pass" },
		"invented domestic":  func(e *HostHealthEvidence) { e.DomesticHTTPS.ObservedIP = "9.9.9.9" },
		"missing probe":      func(e *HostHealthEvidence) { e.ProbeCount-- },
		"unbounded duration": func(e *HostHealthEvidence) { e.ElapsedMS = 5000 },
		"unbounded boottime": func(e *HostHealthEvidence) { e.CompletedUptimeMS = e.StartedUptimeMS + 5000 },
		"bad clock":          func(e *HostHealthEvidence) { e.CompletedUptimeMS = e.StartedUptimeMS - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := e
			change(&bad)
			if ValidateHostHealthEvidence(p, bad) == nil {
				t.Fatal("fabricated evidence accepted")
			}
		})
	}
	failure := runHostHealth(context.Background(), p, func(ctx context.Context, r hostHealthProbe) HostHealthResult {
		if r.role == "dns" {
			return HostHealthResult{Result: "timeout"}
		}
		return hostHealthPassingProbe(ctx, r)
	})
	if failure.Healthy || ValidateHostHealthEvidence(p, failure) != nil {
		t.Fatalf("honest failure invalid: %+v", failure)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	absent := runHostHealth(ctx, p, hostHealthPassingProbe)
	if ValidateHostHealthEvidence(p, absent) != nil {
		t.Fatal("honest not-run canceled result invalid")
	}
	absent.Healthy = true
	if ValidateHostHealthEvidence(p, absent) == nil {
		t.Fatal("unmeasured success accepted")
	}
	ipv6 := hostHealthPlanFixture(true)
	ipv6.IPv6.DirectUnavailable = true
	ipv6.IPv6.UnderlaySource = ""
	ipv6.IPv6.ExpectedDirectIP = ""
	measured := runHostHealth(context.Background(), ipv6, hostHealthPassingProbe)
	if ValidateHostHealthEvidence(ipv6, measured) != nil {
		t.Fatal("explicit IPv6 Direct-unavailable scope rejected")
	}
	measured.IPv6.DirectVerified = true
	if ValidateHostHealthEvidence(ipv6, measured) == nil {
		t.Fatal("unavailable IPv6 Direct promoted to verified")
	}
}

func TestHostHealthPublicEntryRefusesAnotherBootWithoutProbing(t *testing.T) {
	p := hostHealthPlanFixture(false)
	actual, err := trialBootIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p.BootID = "00000000-0000-0000-0000-000000000000"
	if actual == p.BootID {
		p.BootID = "11111111-1111-1111-1111-111111111111"
	}
	e := ProbeHostHealth(context.Background(), p)
	if e.Healthy || e.ProbeCount != 0 || e.Reason != "boot_identity_mismatch" {
		t.Fatalf("stale boot launched probes: %+v", e)
	}
	if err := ValidateHostHealthEvidence(p, e); err != nil {
		t.Fatal(err)
	}
}
