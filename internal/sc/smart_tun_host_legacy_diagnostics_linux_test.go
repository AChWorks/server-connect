//go:build linux

package sc

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func hostLegacyNativeMissingCoreFixture() hostLegacyNativeEvidence {
	e := hostLegacyNativeEvidence{
		pathsBefore: strings.Repeat("a", 64), pathsAfter: strings.Repeat("a", 64),
		namespaceBefore: [2]uint64{1, 2}, namespaceAfter: [2]uint64{1, 2},
	}
	for i := range e.families {
		e.families[i] = hostLegacyNativeFamilyEvidence{
			before:   hostLegacyNativeProcEvidence{observed: true},
			after:    hostLegacyNativeProcEvidence{observed: true},
			executed: true,
		}
	}
	e.families[1].before.err = &os.PathError{Op: "open", Path: "/proc/net/ip6_tables_names", Err: syscall.ENOENT}
	e.families[1].after.err = &os.PathError{Op: "open", Path: "/proc/net/ip6_tables_names", Err: syscall.ENOENT}
	return e
}

func TestHostLegacyNativeUnsupportedClassificationRequiresExactMissingCoreEvidence(t *testing.T) {
	refused := hostLegacyPolicyUnverified()
	if !hostLegacyNativeMissingIPv6Core(refused, hostLegacyNativeMissingCoreFixture()) {
		t.Fatal("complete exact missing-IPv6-core negative evidence was not classified")
	}
	for _, admission := range []error{
		nil, errors.New(refused.Error()),
		Fault("host_ingress_unverified", refused.Error()),
		Fault("foreign_legacy_policy_unverified", "some other failure"),
	} {
		if hostLegacyNativeMissingIPv6Core(admission, hostLegacyNativeMissingCoreFixture()) {
			t.Fatalf("generic/absent/different product refusal was accepted: %v", admission)
		}
	}
	if hostLegacyNativeMissingIPv6Core(refused, hostLegacyNativeEvidence{}) {
		t.Fatal("missing observations were treated as a verified unsupported result")
	}
	cases := []struct {
		name   string
		change func(*hostLegacyNativeEvidence)
	}{
		{"false_untrusted_before", func(e *hostLegacyNativeEvidence) { e.falseBefore = os.ErrPermission }},
		{"false_untrusted_after", func(e *hostLegacyNativeEvidence) { e.falseAfter = os.ErrPermission }},
		{"paths_unobserved", func(e *hostLegacyNativeEvidence) { e.pathsBefore = ""; e.pathsAfter = "" }},
		{"paths_changed", func(e *hostLegacyNativeEvidence) { e.pathsAfter = strings.Repeat("b", 64) }},
		{"namespace_changed", func(e *hostLegacyNativeEvidence) { e.namespaceAfter[1]++ }},
		{"namespace_unobserved", func(e *hostLegacyNativeEvidence) { e.namespaceBefore = [2]uint64{}; e.namespaceAfter = [2]uint64{} }},
		{"ipv4_also_missing", func(e *hostLegacyNativeEvidence) {
			e.families[0].before.err = os.ErrNotExist
			e.families[0].after.err = os.ErrNotExist
		}},
		{"ipv6_supported_empty", func(e *hostLegacyNativeEvidence) { e.families[1].before.err = nil; e.families[1].after.err = nil }},
		{"ipv6_appeared", func(e *hostLegacyNativeEvidence) { e.families[1].after.err = nil }},
		{"ipv6_disappeared", func(e *hostLegacyNativeEvidence) { e.families[1].before.err = nil }},
		{"ipv6_permission", func(e *hostLegacyNativeEvidence) {
			e.families[1].before.err = os.ErrPermission
			e.families[1].after.err = os.ErrPermission
		}},
		{"ipv6_unknown_io", func(e *hostLegacyNativeEvidence) {
			e.families[1].before.err = syscall.EIO
			e.families[1].after.err = syscall.EIO
		}},
		{"ipv6_missing_text_only", func(e *hostLegacyNativeEvidence) {
			e.families[1].before.err = errors.New("no such file or directory")
			e.families[1].after.err = e.families[1].before.err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := hostLegacyNativeMissingCoreFixture()
			tc.change(&e)
			if hostLegacyNativeMissingIPv6Core(refused, e) {
				t.Fatal("unverified evidence authorized unsupported negative QA")
			}
		})
	}
	for i, family := range []string{"ipv4", "ipv6"} {
		for _, tc := range []struct {
			name   string
			change func(*hostLegacyNativeFamilyEvidence)
		}{
			{"before_unobserved", func(f *hostLegacyNativeFamilyEvidence) { f.before.observed = false }},
			{"after_unobserved", func(f *hostLegacyNativeFamilyEvidence) { f.after.observed = false }},
			{"before_nonempty", func(f *hostLegacyNativeFamilyEvidence) { f.before.raw = []byte("nat\n") }},
			{"after_nonempty", func(f *hostLegacyNativeFamilyEvidence) { f.after.raw = []byte("mangle\n") }},
			{"proc_partial", func(f *hostLegacyNativeFamilyEvidence) { f.before.raw = []byte("ra"); f.before.err = syscall.EIO }},
			{"trust_before", func(f *hostLegacyNativeFamilyEvidence) { f.trustBefore = os.ErrPermission }},
			{"trust_after", func(f *hostLegacyNativeFamilyEvidence) { f.trustAfter = os.ErrPermission }},
			{"save_not_executed", func(f *hostLegacyNativeFamilyEvidence) { f.executed = false }},
			{"save_exit_failed", func(f *hostLegacyNativeFamilyEvidence) { f.exit = 3 }},
			{"save_unknown_error", func(f *hostLegacyNativeFamilyEvidence) { f.err = syscall.EIO }},
			{"save_timeout", func(f *hostLegacyNativeFamilyEvidence) { f.timedOut = true }},
			{"save_nonempty", func(f *hostLegacyNativeFamilyEvidence) { f.stdout = []byte("*mangle\n") }},
			{"save_whitespace", func(f *hostLegacyNativeFamilyEvidence) { f.stdout = []byte("\n") }},
			{"save_stderr", func(f *hostLegacyNativeFamilyEvidence) { f.stderr = []byte("warning") }},
		} {
			t.Run(family+"/"+tc.name, func(t *testing.T) {
				e := hostLegacyNativeMissingCoreFixture()
				tc.change(&e.families[i])
				if hostLegacyNativeMissingIPv6Core(refused, e) {
					t.Fatal("partial/unknown/nonempty legacy evidence was accepted")
				}
			})
		}
	}
}
