//go:build linux

package sc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func hostNetfilterPathFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"usr/sbin", "etc/alternatives"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"nft", "legacy"} {
		if err := os.WriteFile(filepath.Join(root, "usr/sbin/xtables-"+mode+"-multi"), []byte("private executable fixture\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range []string{"iptables", "ip6tables"} {
		links := map[string]string{
			"usr/sbin/" + family:                  "/etc/alternatives/" + family,
			"etc/alternatives/" + family:          "/usr/sbin/" + family + "-nft",
			"usr/sbin/" + family + "-nft":         "xtables-nft-multi",
			"usr/sbin/" + family + "-legacy":      "xtables-legacy-multi",
			"usr/sbin/" + family + "-legacy-save": "xtables-legacy-multi",
		}
		for name, target := range links {
			if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestHostNetfilterTrustPreservesPackagedBackendSelection(t *testing.T) {
	root := hostNetfilterPathFixture(t)
	uid := uint32(os.Getuid())
	for _, path := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables", "/usr/sbin/iptables-nft",
		"/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy",
		"/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save"} {
		if err := verifyHostNetfilterPath(root, path, uid); err != nil {
			t.Fatalf("trusted packaged alias %s refused: %v", path, err)
		}
	}
	// A legitimate operator-selected legacy default remains legacy. The
	// raw nft-specific caller can refuse its banner; this helper never
	// silently changes that choice to the nft backend.
	for _, family := range []string{"iptables", "ip6tables"} {
		path := filepath.Join(root, "etc/alternatives", family)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/usr/sbin/"+family+"-legacy", path); err != nil {
			t.Fatal(err)
		}
		if err := verifyHostNetfilterPath(root, "/usr/sbin/"+family, uid); err != nil {
			t.Fatalf("legitimate legacy default refused: %v", err)
		}
		target, err := os.Readlink(path)
		if err != nil || target != "/usr/sbin/"+family+"-legacy" {
			t.Fatal("trust inspection rewrote selected alternatives")
		}
	}
}

func TestHostNetfilterTrustRefusesUntrustedPrivatePaths(t *testing.T) {
	relink := func(t *testing.T, root, path, target string) {
		t.Helper()
		file := filepath.Join(root, path)
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, file); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name   string
		damage func(*testing.T, string)
	}{
		{"writable backend", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "usr/sbin/xtables-nft-multi"), 0775); err != nil {
				t.Fatal(err)
			}
		}},
		{"nonexecutable backend", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "usr/sbin/xtables-nft-multi"), 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"setuid backend", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "usr/sbin/xtables-nft-multi"), 0755|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		}},
		{"setgid backend", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "usr/sbin/xtables-nft-multi"), 0755|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		}},
		{"writable alternatives ancestor", func(t *testing.T, root string) {
			if err := os.Chmod(filepath.Join(root, "etc/alternatives"), 0777); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink ancestor", func(t *testing.T, root string) {
			if err := os.Rename(filepath.Join(root, "usr/sbin"), filepath.Join(root, "usr/sbin-real")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("sbin-real", filepath.Join(root, "usr/sbin")); err != nil {
				t.Fatal(err)
			}
		}},
		{"arbitrary absolute target", func(t *testing.T, root string) {
			relink(t, root, "etc/alternatives/iptables", "/tmp/untrusted-iptables")
		}},
		{"escaping relative target", func(t *testing.T, root string) {
			relink(t, root, "etc/alternatives/iptables", "../../../tmp/untrusted-iptables")
		}},
		{"cross-family target", func(t *testing.T, root string) {
			relink(t, root, "etc/alternatives/iptables", "/usr/sbin/ip6tables-nft")
		}},
		{"explicit nft remapped to legacy", func(t *testing.T, root string) {
			relink(t, root, "usr/sbin/iptables-nft", "xtables-legacy-multi")
		}},
		{"alias loop", func(t *testing.T, root string) {
			relink(t, root, "etc/alternatives/iptables", "/usr/sbin/iptables")
		}},
		{"backend symlink", func(t *testing.T, root string) {
			relink(t, root, "usr/sbin/xtables-nft-multi", "xtables-legacy-multi")
		}},
		{"missing backend", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "usr/sbin/xtables-nft-multi")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := hostNetfilterPathFixture(t)
			tc.damage(t, root)
			if err := verifyHostNetfilterPath(root, "/usr/sbin/iptables", uint32(os.Getuid())); ErrorCode(err) != "host_netfilter_untrusted" {
				t.Fatalf("untrusted path admitted: %v", err)
			}
		})
	}
	root := hostNetfilterPathFixture(t)
	if err := verifyHostNetfilterPath(root, "/usr/sbin/iptables", uint32(os.Getuid())+1); err == nil {
		t.Fatal("untrusted owner accepted")
	}
	for _, binary := range []string{"iptables", "/tmp/iptables", "/usr/sbin/xtables-nft-multi", "/usr/sbin/iptables/../iptables"} {
		if err := verifyHostNetfilterPath(root, binary, uint32(os.Getuid())); err == nil {
			t.Fatalf("unapproved entry point admitted: %q", binary)
		}
	}
}

// Version probes require no privileged firewall dump and mutate no policies.
// Missing packages are explicitly NOT_RUN, not evidence of a trusted backend.
func TestHostNetfilterPackagedAliasesActualVersion(t *testing.T) {
	for _, binary := range []string{"/usr/sbin/iptables", "/usr/sbin/ip6tables", "/usr/sbin/iptables-nft",
		"/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy",
		"/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save"} {
		t.Run(filepath.Base(binary), func(t *testing.T) {
			if _, err := os.Lstat(binary); os.IsNotExist(err) {
				t.Skip("NOT_RUN: packaged native netfilter alias absent")
			}
			version, err := runReadOnlyHostNetfilter(binary, "-V")
			if err != nil {
				t.Fatal(err)
			}
			text := string(version)
			if !strings.Contains(text, "tables") || !strings.Contains(text, " v") ||
				(!strings.Contains(text, "(nf_tables)") && !strings.Contains(text, "(legacy)")) {
				t.Fatalf("native backend banner unverified: %q", text)
			}
			if strings.Contains(binary, "-legacy") && !strings.Contains(text, "(legacy)") ||
				strings.HasSuffix(binary, "-nft") && !strings.Contains(text, "(nf_tables)") {
				t.Fatalf("explicit backend changed: %q", text)
			}
			t.Log(strings.TrimSpace(text))
		})
	}
}
