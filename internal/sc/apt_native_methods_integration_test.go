package sc

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This uses genuine Debian APT and the already-live pinned sing-box/VLESS
// proxy from TestRealPinnedCoreProxyOnly. Every fixture source is loopback;
// no host APT configuration, real package installation or root mutation.
func testAPTNativeMirrorAndPDiff(t *testing.T, proxyURL *url.URL) {
	t.Helper()
	if err := verifyNativeAPTMethods(); err != nil {
		t.Fatalf("native helpers must be verified before the APT test: %v", err)
	}
	// Large initial index and tiny diff make APT prefer its real rred PDiff
	// acquisition path. A second update must not fall back to a full index.
	var oldBuilder strings.Builder
	for i := 0; i < 130; i++ {
		fmt.Fprintf(&oldBuilder, "Package: qa-old-%03d\nVersion: 1.0\nArchitecture: amd64\nMaintainer: Disposable QA <qa@invalid.test>\nDescription: old package entry %03d\n\n", i, i)
	}
	oldIndex := []byte(oldBuilder.String())
	addition := []byte("Package: qa-pdiff-new\nVersion: 1.0\nArchitecture: amd64\nMaintainer: Disposable QA <qa@invalid.test>\nDescription: PDiff update only\n\n")
	newIndex := append(append([]byte(nil), oldIndex...), addition...)
	patchName := "2026-10-22-0000.00"
	patch := []byte(fmt.Sprintf("%da\n%s.\n", bytes.Count(oldIndex, []byte("\n")), addition))
	zippedPatch := gzipTestBytes(t, patch)
	oldZipped := gzipTestBytes(t, oldIndex)
	newZipped := gzipTestBytes(t, newIndex)
	hashline := func(path string, data []byte) string {
		sum := sha256.Sum256(data)
		return fmt.Sprintf(" %x %d %s\n", sum, len(data), path)
	}
	diffIndex := fmt.Sprintf("SHA256-Current: %x %d\nSHA256-History:\n%sSHA256-Patches:\n%sSHA256-Download:\n%s",
		sha256.Sum256(newIndex), len(newIndex),
		hashline(patchName, oldIndex),
		hashline(patchName, patch),
		hashline(patchName+".gz", zippedPatch))
	oldRelease := testRelease(oldIndex, oldZipped, nil, hashline)
	newRelease := testRelease(newIndex, newZipped, []byte(diffIndex), hashline)
	var changed atomic.Bool
	var diffIndexHits, patchHits, forbiddenFullHits, mirrorListHits atomic.Int64
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dists/qa/Release":
			if changed.Load() {
				_, _ = w.Write([]byte(newRelease))
			} else {
				_, _ = w.Write([]byte(oldRelease))
			}
		case "/dists/qa/main/binary-amd64/Packages", "/dists/qa/main/binary-amd64/Packages.gz":
			if changed.Load() {
				forbiddenFullHits.Add(1)
				http.Error(w, "full index fallback forbidden in PDiff acceptance", http.StatusServiceUnavailable)
				return
			}
			if strings.HasSuffix(r.URL.Path, ".gz") {
				_, _ = w.Write(oldZipped)
			} else {
				_, _ = w.Write(oldIndex)
			}
		case "/dists/qa/main/binary-amd64/Packages.diff/Index":
			if !changed.Load() {
				http.NotFound(w, r)
				return
			}
			diffIndexHits.Add(1)
			_, _ = w.Write([]byte(diffIndex))
		case "/dists/qa/main/binary-amd64/Packages.diff/" + patchName + ".gz":
			if !changed.Load() {
				http.NotFound(w, r)
				return
			}
			patchHits.Add(1)
			_, _ = w.Write(zippedPatch)
		default:
			http.NotFound(w, r)
		}
	}))
	defer origin.Close()
	mirrorList := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mirrors.txt" {
			http.NotFound(w, r)
			return
		}
		mirrorListHits.Add(1)
		_, _ = fmt.Fprintln(w, origin.URL+"/")
	}))
	defer mirrorList.Close()
	dir := t.TempDir()
	lists, archives := filepath.Join(dir, "lists"), filepath.Join(dir, "archives")
	for _, name := range []string{lists, filepath.Join(lists, "partial"), archives} {
		if err := os.MkdirAll(name, 0755); err != nil {
			t.Fatal(err)
		}
	}
	sourceFile := filepath.Join(dir, "sources.list")
	// Debian's native mirror+http alias is required; a fake mirror method
	// would not be allowed by verifyNativeAPTMethods above.
	mirrorURL := "mirror+" + mirrorList.URL + "/mirrors.txt"
	if err := os.WriteFile(sourceFile, []byte("deb [trusted=yes] "+mirrorURL+" qa main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"update",
		"-o", "Dir::Etc::sourcelist=" + sourceFile,
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists=" + lists,
		"-o", "Dir::Cache::archives=" + archives,
		"-o", "Dir::Cache::pkgcache=/dev/null",
		"-o", "Dir::Cache::srcpkgcache=/dev/null",
		"-o", "APT::Get::List-Cleanup=0",
		"-o", "Debug::NoLocking=1"}
	if code, err := aptThroughSelectedProxy(systemAPTGet, args, t.TempDir(), proxyURL); err != nil || code != 0 {
		t.Fatalf("native mirror+http baseline update through pinned VLESS failed: exit=%d err=%v", code, err)
	}
	if mirrorListHits.Load() == 0 {
		t.Fatal("native mirror+http handler never acquired the local mirror list")
	}
	changed.Store(true)
	if code, err := aptThroughSelectedProxy(systemAPTGet, args, t.TempDir(), proxyURL); err != nil || code != 0 {
		t.Fatalf("native PDiff update through pinned VLESS failed: exit=%d err=%v, diff_index_hits=%d patch_hits=%d forbidden_full=%d",
			code, err, diffIndexHits.Load(), patchHits.Load(), forbiddenFullHits.Load())
	}
	if diffIndexHits.Load() == 0 || patchHits.Load() == 0 || forbiddenFullHits.Load() != 0 {
		t.Fatalf("native PDiff path not proved: diff_index_hits=%d patch_hits=%d full_fallback=%d",
			diffIndexHits.Load(), patchHits.Load(), forbiddenFullHits.Load())
	}
	cache := exec.Command("/usr/bin/apt-cache",
		"-o", "Dir::Etc::sourcelist="+sourceFile,
		"-o", "Dir::Etc::sourceparts=-",
		"-o", "Dir::State::lists="+lists,
		"show", "qa-pdiff-new")
	out, err := cache.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("Package: qa-pdiff-new")) {
		t.Fatalf("native rred did not produce the new APT index (credential-free apt-cache check): %v", err)
	}
}

func gzipTestBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testRelease(index, zipped, diffIndex []byte, hashline func(string, []byte) string) string {
	body := "Origin: Server Connect local QA\nLabel: SC local PDiff QA\nSuite: qa\nCodename: qa\nArchitectures: amd64\nComponents: main\n"
	body += "Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\nSHA256:\n"
	body += hashline("main/binary-amd64/Packages", index)
	body += hashline("main/binary-amd64/Packages.gz", zipped)
	if diffIndex != nil {
		body += hashline("main/binary-amd64/Packages.diff/Index", diffIndex)
	}
	return body
}
