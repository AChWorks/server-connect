package sc

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestInstallerHostTargetExactIdentity(t *testing.T) {
	for _, version := range []string{"12", "13"} {
		for _, quote := range []string{"", `"`, `'`} {
			raw := []byte("# native identity\nPRETTY_NAME=\"Debian GNU/Linux\"\nID=" + quote + "debian" + quote + "\nVERSION_ID=" + quote + version + quote + "\n")
			got, err := installerHostTarget(raw, "linux", "amd64", "x86_64")
			if err != nil || got != "debian-"+version+"-amd64" {
				t.Fatalf("canonical supported identity refused: %q, %v", got, err)
			}
		}
	}
	bad := []string{
		"", "ID=debian\n", "VERSION_ID=12\n", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=12\n",
		"ID=debian\nVERSION_ID=11\n", "ID=debian\nVERSION_ID=14\n", "ID=debian\nVERSION_ID=12.0\n",
		"ID=debian\nID=debian\nVERSION_ID=12\n", "ID=debian\nVERSION_ID=12\nVERSION_ID=13\n",
		"ID=debian\nid=ubuntu\nVERSION_ID=12\n", "ID=debian\nversion_id=12\n",
		"ID =ubuntu\nID=debian\nVERSION_ID=12\n", "export ID=debian\nVERSION_ID=12\n",
		"ID=\"debian\nVERSION_ID=12\n", "ID=de\\bian\nVERSION_ID=12\n",
		"ID=$(printf debian)\nVERSION_ID=12\n", "ID=debian\nVERSION_ID=12;true\n",
		"ID=debian\nVERSION_ID=12\n\x00", "ID=debian\nVERSION_ID=12\n\xff",
		"ID=debian\nVERSION_ID=12\n" + strings.Repeat("#", installerMetadataMaxBytes),
	}
	for _, raw := range bad {
		if got, err := installerHostTarget([]byte(raw), "linux", "amd64", "x86_64"); got != "" || ErrorCode(err) != "unsupported_host" {
			t.Fatalf("unsupported or ambiguous identity admitted: %q: %q, %v", raw, got, err)
		}
	}
	for _, platform := range [][3]string{{"freebsd", "amd64", "x86_64"}, {"linux", "arm64", "x86_64"}, {"linux", "amd64", "aarch64"}} {
		if _, err := installerHostTarget([]byte("ID=debian\nVERSION_ID=12\n"), platform[0], platform[1], platform[2]); ErrorCode(err) != "unsupported_host" {
			t.Fatalf("non-native platform admitted: %v: %v", platform, err)
		}
	}
}

func TestInstallerManifestBindsExactHost(t *testing.T) {
	for _, target := range []string{"debian-12-amd64", "debian-13-amd64"} {
		raw := []byte(`{"schema":1,"target":"` + target + `","source_state":"clean","other_metadata":{"version":"kept"}}`)
		if err := verifyInstallerManifestTarget(raw, target); err != nil {
			t.Fatal(err)
		}
		other := "debian-12-amd64"
		if target == other {
			other = "debian-13-amd64"
		}
		if err := verifyInstallerManifestTarget(raw, other); ErrorCode(err) != "installer_target_mismatch" {
			t.Fatalf("opposite-target bundle admitted: %v", err)
		}
	}
	bad := []string{
		``, `null`, `[]`, `{}`, `{"schema":1}`, `{"target":"debian-12-amd64"}`,
		`{"schema":1,"target":null}`, `{"schema":1,"target":12}`, `{"schema":1,"target":{}}`,
		`{"schema":0,"target":"debian-12-amd64"}`, `{"schema":1.0,"target":"debian-12-amd64"}`,
		`{"schema":1,"target":"debian-14-amd64"}`, `{"schema":1,"target":"debian-12-arm64"}`,
		`{"schema":1,"target":"debian-12-amd64","target":"debian-13-amd64"}`,
		`{"schema":1,"target":"debian-12-amd64","Target":"debian-12-amd64"}`,
		`{"schema":1,"Target":"debian-12-amd64"}`, `{"Schema":1,"target":"debian-12-amd64"}`,
		`{"schema":1,"schema":1,"target":"debian-12-amd64"}`,
		`{"schema":1,"target":"debian-12-amd64","other":{"key":1,"KEY":2}}`,
		`{"schema":1,"target":"debian-12-amd64"} {}`,
		`{"schema":1,"target":"debian-12-amd64",}`,
		`{"schema":1,"target":"debian-12-amd64","other":` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40) + `}`,
		strings.Repeat(" ", installerMetadataMaxBytes) + `{"schema":1,"target":"debian-12-amd64"}`,
		"{\"schema\":1,\"target\":\"debian-12-amd64\",\"other\":\"\xff\"}",
	}
	for _, raw := range bad {
		if err := verifyInstallerManifestTarget([]byte(raw), "debian-12-amd64"); ErrorCode(err) != "installer_target_invalid" {
			t.Fatalf("ambiguous or malformed manifest admitted: %q: %v", raw, err)
		}
	}
}

func TestInstallerMetadataReaderTrustAndBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	payload := []byte(`{"schema":1,"target":"debian-12-amd64"}`)
	manifest := filepath.Join(root, "manifest.json")
	if err := os.WriteFile(manifest, payload, 0644); err != nil {
		t.Fatal(err)
	}
	if got, err := readInstallerFileAt(root, manifest, uid, 128); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("safe public metadata refused: %v", err)
	}
	refuse := func(path string, owner uint32, limit int64) {
		t.Helper()
		if _, err := readInstallerFileAt(root, path, owner, limit); ErrorCode(err) != "installer_target_invalid" {
			t.Fatalf("unsafe metadata admitted: %s, %v", path, err)
		}
	}
	refuse(manifest, uid+1, 128)
	refuse(manifest, uid, int64(len(payload)-1))
	refuse(filepath.Join(root, "missing"), uid, 128)
	refuse(root, uid, 128)
	refuse(root+"/../outside", uid, 128)
	refuse("manifest.json", uid, 128)
	if err := os.Chmod(manifest, 0664); err != nil {
		t.Fatal(err)
	}
	refuse(manifest, uid, 128)
	if err := os.Chmod(manifest, 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "manifest-link")
	if err := os.Symlink(manifest, link); err != nil {
		t.Fatal(err)
	}
	refuse(link, uid, 128)
	child := filepath.Join(root, "parent")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	childFile := filepath.Join(child, "manifest.json")
	if err := os.WriteFile(childFile, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(child, 0777); err != nil {
		t.Fatal(err)
	}
	refuse(childFile, uid, 128)
	if err := os.Chmod(child, 0700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(root, "parent-link")
	if err := os.Symlink(child, parentLink); err != nil {
		t.Fatal(err)
	}
	refuse(filepath.Join(parentLink, "manifest.json"), uid, 128)
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	refuse(fifo, uid, 128)
	empty := filepath.Join(root, "empty")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	refuse(empty, uid, 128)
}

func TestDebian12InstallationDoesNotAdmitNativeTrials(t *testing.T) {
	if err := requireNativeTrialTarget("debian-13-amd64"); err != nil {
		t.Fatalf("existing native target refused: %v", err)
	}
	for _, target := range []string{"debian-12-amd64", "debian-14-amd64", "", "debian-13-arm64"} {
		err := requireNativeTrialTarget(target)
		if ErrorCode(err) != "trial_unsupported" || err.Error() != nativeTrialPlatformRefusal {
			t.Fatalf("new installation target widened native Apply: %q, %v", target, err)
		}
	}
}
