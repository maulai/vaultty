package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	d := New()
	if d.Version != schemaVersion || len(d.Folders) != 1 || d.Folders[0].ID != DefaultFolderID || d.Hosts == nil {
		t.Fatalf("New() = %+v", d)
	}
}

func TestFolders(t *testing.T) {
	d := New()
	prod := d.PutFolder(Folder{Name: "Prod"})
	web := d.PutHost(Host{Name: "web", FolderID: prod})
	d.PutHost(Host{Name: "db", FolderID: DefaultFolderID})

	if d.FolderSize(prod) != 1 || d.FolderSize(DefaultFolderID) != 1 {
		t.Fatalf("folder sizes: %d %d", d.FolderSize(prod), d.FolderSize(DefaultFolderID))
	}
	if err := d.DeleteFolder(DefaultFolderID); !errors.Is(err, ErrDefaultFolder) {
		t.Fatalf("DeleteFolder(default) = %v", err)
	}
	if err := d.DeleteFolder(prod); err != nil {
		t.Fatal(err)
	}
	if h, _ := d.Host(web); h.FolderID != DefaultFolderID {
		t.Fatalf("host of deleted folder is in %q", h.FolderID)
	}
	if _, ok := d.Folder(prod); ok {
		t.Fatal("folder still exists")
	}
}

func TestHosts(t *testing.T) {
	d := New()
	f := d.PutFolder(Folder{Name: "f"})
	id := d.PutHost(Host{Name: "a"})
	d.PutHost(Host{ID: id, Name: "renamed"})
	if h, _ := d.Host(id); h.Name != "renamed" || len(d.Hosts) != 1 {
		t.Fatalf("PutHost update: %+v", d.Hosts)
	}
	if err := d.MoveHost(id, f); err != nil {
		t.Fatal(err)
	}
	if err := d.MoveHost(id, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MoveHost(missing folder) = %v", err)
	}
	if err := d.MoveHost("missing", f); !errors.Is(err, ErrNotFound) {
		t.Fatalf("MoveHost(missing host) = %v", err)
	}
	d.DeleteHost(id)
	if len(d.Hosts) != 0 {
		t.Fatal("DeleteHost")
	}
}

func TestProfiles(t *testing.T) {
	d := New()
	p := d.PutProfile(KeyProfile{Name: "k"})
	h := d.PutHost(Host{Auth: AuthKey, KeyProfileID: p})
	if err := d.DeleteProfile(p); !errors.Is(err, ErrProfileInUse) {
		t.Fatalf("DeleteProfile(in use) = %v", err)
	}
	d.DeleteHost(h)
	if err := d.DeleteProfile(p); err != nil || len(d.KeyProfiles) != 0 {
		t.Fatalf("DeleteProfile = %v, %+v", err, d.KeyProfiles)
	}
}

func TestTrust(t *testing.T) {
	var d Data
	d.Trust("a", "old")
	d.Trust("b", "b")
	d.Trust("a", "new")
	if len(d.KnownHosts) != 2 {
		t.Fatalf("KnownHosts = %+v", d.KnownHosts)
	}
	for _, k := range d.KnownHosts {
		if k.Host == "a" && k.Key != "new" {
			t.Fatalf("old key kept: %+v", d.KnownHosts)
		}
	}
}

func TestNormalize(t *testing.T) {
	d := Data{Hosts: []Host{{ID: "h", FolderID: "gone"}}}
	d.normalize()
	if _, ok := d.Folder(DefaultFolderID); !ok || d.Hosts[0].FolderID != DefaultFolderID {
		t.Fatalf("normalize = %+v", d)
	}
}

func TestPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	inHome := filepath.Join(home, ".ssh", "id_test")
	if got := PortablePath(inHome); got != "~/.ssh/id_test" {
		t.Errorf("PortablePath(%q) = %q", inHome, got)
	}
	if got := ResolvePath("~/.ssh/id_test"); got != inHome {
		t.Errorf("ResolvePath = %q, want %q", got, inHome)
	}
	if got := ExpandPath(`  "~/x"  `); got != filepath.Join(home, "x") {
		t.Errorf("ExpandPath with quotes = %q", got)
	}
	outside := filepath.Join(filepath.VolumeName(home)+string(filepath.Separator), "vaultty-test", "id")
	if got := PortablePath(outside); got != outside {
		t.Errorf("PortablePath(%q) = %q, want it unchanged", outside, got)
	}
}

func TestReadKey(t *testing.T) {
	if _, err := (KeyProfile{}).ReadKey(); !errors.Is(err, ErrNoKey) {
		t.Fatalf("empty embedded key: %v", err)
	}
	if b, err := (KeyProfile{Key: "pem"}).ReadKey(); err != nil || string(b) != "pem" {
		t.Fatalf("embedded key: %q %v", b, err)
	}
	dir := t.TempDir()
	small := filepath.Join(dir, "small")
	big := filepath.Join(dir, "big")
	os.WriteFile(small, []byte("pem"), 0o600)
	os.WriteFile(big, []byte(strings.Repeat("x", maxKeyFile+1)), 0o600)
	if b, err := (KeyProfile{Source: KeySourceFile, Path: small}).ReadKey(); err != nil || string(b) != "pem" {
		t.Fatalf("file key: %q %v", b, err)
	}
	if _, err := (KeyProfile{Source: KeySourceFile, Path: big}).ReadKey(); !errors.Is(err, ErrKeyTooLarge) {
		t.Fatalf("large file: %v", err)
	}
}
