//go:build linux

package sc

// Netfilter readers execute only these fixed Debian entry points. Preserve the
// selected iptables/ip6tables alternatives backend and argv[0]; resolving a
// trusted alias never grants authority to select an unrelated executable.
import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func hostNetfilterUntrusted() error {
	return Fault("host_netfilter_untrusted", "fixed native netfilter executable ownership or backend path is unverified")
}

func hostNetfilterAliasGraph(binary string) (map[string][]string, error) {
	switch binary {
	case "/usr/sbin/iptables", "/usr/sbin/ip6tables",
		"/usr/sbin/iptables-nft", "/usr/sbin/iptables-legacy", "/usr/sbin/ip6tables-legacy",
		"/usr/sbin/iptables-legacy-save", "/usr/sbin/ip6tables-legacy-save":
	default:
		return nil, hostNetfilterUntrusted()
	}
	graph := map[string][]string{
		"/usr/sbin/xtables-nft-multi":    nil,
		"/usr/sbin/xtables-legacy-multi": nil,
	}
	for _, family := range []string{"iptables", "ip6tables"} {
		base, alternative := "/usr/sbin/"+family, "/etc/alternatives/"+family
		graph[base] = []string{alternative, base + "-nft", base + "-legacy"}
		graph[alternative] = []string{base + "-nft", base + "-legacy"}
		graph[base+"-nft"] = []string{"/usr/sbin/xtables-nft-multi"}
		graph[base+"-legacy"] = []string{"/usr/sbin/xtables-legacy-multi"}
		graph[base+"-legacy-save"] = []string{"/usr/sbin/xtables-legacy-multi"}
	}
	return graph, nil
}

// root/ownerUID are private-filesystem fixture parameters. Production always
// supplies "/" and UID 0. Every alias and ancestor is checked before following
// the next edge; only the matching packaged alternatives graph is supported.
func verifyHostNetfilterPath(root, binary string, ownerUID uint32) error {
	graph, err := hostNetfilterAliasGraph(binary)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return hostNetfilterUntrusted()
	}
	current := binary
	seen := map[string]bool{}
	for depth := 0; depth < 8; depth++ {
		next, known := graph[current]
		if !known || seen[current] {
			return hostNetfilterUntrusted()
		}
		seen[current] = true
		parts := strings.Split(strings.TrimPrefix(current, "/"), "/")
		physical := root
		var leaf os.FileInfo
		for i := 0; i <= len(parts); i++ {
			if i > 0 {
				physical = filepath.Join(physical, parts[i-1])
			}
			info, err := os.Lstat(physical)
			if err != nil {
				return hostNetfilterUntrusted()
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != ownerUID {
				return hostNetfilterUntrusted()
			}
			if i < len(parts) {
				if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
					return hostNetfilterUntrusted()
				}
			} else {
				leaf = info
			}
		}
		if leaf.Mode()&os.ModeSymlink == 0 {
			// A backend endpoint is a regular executable, not another alias
			// or a replacement entry point with unexplained semantics.
			if len(next) != 0 || verifyTrustedIPPath(root, physical, ownerUID) != nil {
				return hostNetfilterUntrusted()
			}
			return nil
		}
		target, err := os.Readlink(physical)
		if err != nil || target == "" || len(target) > 4096 {
			return hostNetfilterUntrusted()
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(current), target)
		}
		target = filepath.Clean(target)
		allowed := false
		for _, candidate := range next {
			if target == candidate {
				allowed = true
				break
			}
		}
		if !allowed {
			return hostNetfilterUntrusted()
		}
		current = target
	}
	return hostNetfilterUntrusted()
}
