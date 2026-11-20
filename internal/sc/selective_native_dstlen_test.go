package sc

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Native iproute2 policy JSON represents a destination as "dst" plus
// "dstlen". Treating that address alone as a /32 or /128 can hide a
// higher-precedence overlapping prefix and produce a misleading preview.
// Native iproute2 may encode dst and dstlen separately. The same parser
// is used for the recovery ownership check, independently of the retired
// advisory planner.
func TestSelectiveRuleDestinationNativePrefixLength(t *testing.T) {
	for _, tt := range []struct {
		name, dst, dstlen string
		ipv6              bool
		expected          string
		reject            bool
	}{
		{"ipv4_prefix", "8.8.8.0", "24", false, "8.8.8.0/24", false},
		{"ipv6_prefix", "2606:4700::", "32", true, "2606:4700::/32", false},
		{"ipv4_invalid_length", "9.9.9.0", "33", false, "", true},
		{"ipv6_invalid_length", "2607::", "129", true, "", true},
		{"ipv4_null_length", "9.9.9.0", "null", false, "", true},
		{"ipv4_conflicting_cidr", "9.9.9.0/24", "25", false, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			row := map[string]json.RawMessage{
				"dst":    json.RawMessage(fmt.Sprintf("%q", tt.dst)),
				"dstlen": json.RawMessage(tt.dstlen),
			}
			prefix, constrained, err := selectiveRuleDestination(row, tt.ipv6)
			if tt.reject {
				if ErrorCode(err) != "route_plan_uncertain" || prefix.IsValid() || constrained {
					t.Fatalf("unsupported native prefix accepted: %v %v %v", prefix, constrained, err)
				}
			} else if err != nil || !constrained || prefix.String() != tt.expected {
				t.Fatalf("valid native prefix rejected: %v %v %v", prefix, constrained, err)
			}
		})
	}
}

// The parser itself must reject null. A planner-only negative case can
// pass accidentally when an invalid 9.9.9.0/0 is rejected as noncanonical.
func TestSelectiveRuleDestinationNullLengthIsInvalid(t *testing.T) {
	cases := []struct {
		name, dst string
		ipv6      bool
	}{
		{"ipv4_native_zero", "0.0.0.0", false},
		{"ipv6_native_zero", "::", true},
		{"ipv4_cidr_zero", "0.0.0.0/0", false},
		{"ipv6_cidr_zero", "::/0", true},
		{"ipv4_all", "all", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]json.RawMessage{
				"dst":    json.RawMessage(fmt.Sprintf("%q", tc.dst)),
				"dstlen": json.RawMessage("null"),
			}
			prefix, constrained, err := selectiveRuleDestination(row, tc.ipv6)
			if ErrorCode(err) != "route_plan_uncertain" || prefix.IsValid() || constrained {
				t.Fatalf("null dstlen accepted: prefix=%v constrained=%v err=%v", prefix, constrained, err)
			}
		})
	}
}

func TestSelectiveRuleDestinationNumericZeroIsValid(t *testing.T) {
	for _, tc := range []struct {
		name, dst   string
		ipv6        bool
		constrained bool
	}{
		{"ipv4_native_zero", "0.0.0.0", false, true},
		{"ipv6_native_zero", "::", true, true},
		{"ipv4_cidr_zero", "0.0.0.0/0", false, true},
		{"ipv6_cidr_zero", "::/0", true, true},
		{"ipv4_all", "all", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := map[string]json.RawMessage{
				"dst":    json.RawMessage(fmt.Sprintf("%q", tc.dst)),
				"dstlen": json.RawMessage("0"),
			}
			prefix, constrained, err := selectiveRuleDestination(row, tc.ipv6)
			if err != nil || constrained != tc.constrained ||
				(tc.constrained && (!prefix.IsValid() || prefix.Bits() != 0)) ||
				(!tc.constrained && prefix.IsValid()) {
				t.Fatalf("valid numeric /0 was rejected: prefix=%v constrained=%v err=%v", prefix, constrained, err)
			}
		})
	}
}

func TestSelectiveIntDoesNotNormalizeNullToZero(t *testing.T) {
	if number, valid := selectiveInt(json.RawMessage("null")); valid {
		t.Fatalf("JSON null was accepted as integer %d", number)
	}
	for _, raw := range []string{"0", "\"0\""} {
		if number, valid := selectiveInt(json.RawMessage(raw)); !valid || number != 0 {
			t.Fatalf("valid numeric zero %s was rejected: %d %v", raw, number, valid)
		}
	}
}
