package sc

// Shared Native routing CIDR/domain acceptance. Retained from the retired
// synthetic TUN compiler because saved operator rules still use these
// canonicalization and PSL constraints.
import (
	"errors"
	"golang.org/x/net/publicsuffix"
	"net/netip"
	"regexp"
	"strings"
)

var smartTUNDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func canonicalSmartTUNDomain(raw string, suffix bool) (string, error) {
	name := strings.ToLower(raw)
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "/:*\\ ") {
		return "", errors.New("invalid operator domain")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("IP address cannot be a domain exception")
	}
	labels := strings.Split(name, ".")
	if !suffix && len(labels) < 2 {
		return "", errors.New("exact domain exception requires a fully qualified name")
	}
	for _, label := range labels {
		if !smartTUNDomainLabel.MatchString(label) {
			return "", errors.New("invalid operator domain label")
		}
	}
	if suffix {
		// Offline PSL from the pinned Go module includes ICANN and PRIVATE
		// boundaries (e.g. co.uk, com.au, github.io, blogspot.com),
		// with wildcard/exception semantics. A dot is not proof of
		// registrability. Unknown/unmanaged TLDs fail closed until the
		// pinned PSL snapshot is updated, without relying on DNS.
		root, icann := publicsuffix.PublicSuffix(name)
		if root == name {
			return "", errors.New("whole public suffix is not an operator domain exception")
		}
		if !icann && !strings.Contains(root, ".") {
			return "", errors.New("unrecognized top-level public suffix")
		}
		if _, err := publicsuffix.EffectiveTLDPlusOne(name); err != nil {
			return "", errors.New("domain suffix has no registrable parent")
		}
	}
	return name, nil
}

func canonicalRoutePrefixFamily(raw string, ipv6 bool) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(raw)
	if err != nil || !p.IsValid() || p.Addr().Is6() != ipv6 ||
		p.Bits() == 0 || p.Masked().String() != raw {
		return netip.Prefix{}, errors.New("invalid or noncanonical CIDR")
	}
	return p, nil
}

func canonicalRoutePrefix(raw string) (netip.Prefix, error) {
	return canonicalRoutePrefixFamily(raw, false)
}

func routePrefixesOverlap(a, b netip.Prefix) bool {
	return a.Addr().Is4() == b.Addr().Is4() && (a.Contains(b.Addr()) || b.Contains(a.Addr()))
}
