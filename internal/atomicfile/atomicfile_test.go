package atomicfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileFollowsSymlink checks that a vault linked into a synced folder
// keeps being written there.
func TestWriteFileFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "synced", "vault.enc")
	if err := os.Mkdir(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "vault.enc")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("cannot create symlinks:", err)
	}
	isLink := func() bool {
		fi, err := os.Lstat(link)
		return err == nil && fi.Mode()&fs.ModeSymlink != 0
	}

	if err := WriteFile(link, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !isLink() {
		t.Fatal("WriteFile replaced the link")
	}
	if b, err := os.ReadFile(target); err != nil || string(b) != "new" {
		t.Fatalf("target holds %q, %v; want \"new\"", b, err)
	}

	// e.g. the synced folder is not mounted
	if err := os.RemoveAll(filepath.Dir(target)); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(link, []byte("newer"), 0o600); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("WriteFile through a dangling link: %v, want fs.ErrNotExist", err)
	}
	if !isLink() {
		t.Fatal("WriteFile replaced the dangling link")
	}
}
