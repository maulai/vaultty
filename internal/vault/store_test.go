package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

const fixturePassword = "fixture-password"

// cheapKDF keeps tests fast; tests about the real defaults do not call it.
func cheapKDF(t *testing.T) {
	old := defaultKDF
	defaultKDF = kdfParams{time: 1, memory: 64, threads: 1}
	t.Cleanup(func() { defaultKDF = old })
}

// copyFixture copies the golden vault, written by an earlier release, to a temp dir.
func copyFixture(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join("testdata", "v4.vault"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v4.vault")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureData(t *testing.T) Data {
	b, err := os.ReadFile(filepath.Join("testdata", "v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOpenFixture(t *testing.T) {
	path := copyFixture(t)
	s, d, err := Open(path, fixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if want := fixtureData(t); !reflect.DeepEqual(d, want) {
		t.Fatalf("Open(fixture) =\n%+v\nwant\n%+v", d, want)
	}

	// The fixture uses 64 MiB; Open re-encrypts it with the current default.
	b, _ := os.ReadFile(path)
	h, _, err := parse(b)
	if err != nil || h.kdf != defaultKDF {
		t.Fatalf("after Open the KDF is %+v (err %v), want %+v", h.kdf, err, defaultKDF)
	}
	s2, d2, err := Open(path, fixturePassword)
	if err != nil || !reflect.DeepEqual(d2, d) {
		t.Fatalf("reopen after upgrade: %v", err)
	}
	s2.Close()
}

// TestJSONKeys guards the on-disk field names.
func TestJSONKeys(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "v4.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(fixtureData(t))
	if err != nil {
		t.Fatal(err)
	}
	var a, b any
	json.Unmarshal(want, &a)
	json.Unmarshal(got, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("marshaled JSON differs from the fixture:\n%s", got)
	}
}

func TestHeaderLayout(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.vault")
	s, _, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	b, _ := os.ReadFile(path)
	if string(b[:7]) != "SSHVLT2" || b[7] != 2 || b[8] != 1 {
		t.Fatalf("header starts with %q % x", b[:7], b[7:9])
	}
	if got := (kdfParams{binary.BigEndian.Uint32(b[9:13]), binary.BigEndian.Uint32(b[13:17]), b[17]}); got != (kdfParams{3, 256 * 1024, 4}) {
		t.Fatalf("KDF params = %+v", got)
	}
	if len(b) < headerLen+16 {
		t.Fatalf("file too short: %d", len(b))
	}
}

func TestOpenErrors(t *testing.T) {
	cheapKDF(t)
	good := func() []byte {
		path := filepath.Join(t.TempDir(), "v")
		s, _, err := Create(path, "correct horse battery", false)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		b, _ := os.ReadFile(path)
		return b
	}()
	patch := func(off int, v ...byte) []byte {
		b := bytes.Clone(good)
		copy(b[off:], v)
		return b
	}
	for _, tc := range []struct {
		name string
		file []byte
		pw   string
		want error
	}{
		{"wrong password", good, "wrong password!!", ErrWrongPassword},
		{"truncated", good[:20], "correct horse battery", ErrFormat},
		{"bad magic", patch(0, 'X'), "correct horse battery", ErrFormat},
		{"newer format", patch(7, 3), "correct horse battery", ErrNewerVault},
		{"unknown kdf", patch(8, 9), "correct horse battery", ErrFormat},
		{"time zero", patch(9, 0, 0, 0, 0), "correct horse battery", ErrFormat},
		{"memory huge", patch(13, 0xff, 0xff, 0xff, 0xff), "correct horse battery", ErrFormat},
		{"threads zero", patch(17, 0), "correct horse battery", ErrFormat},
		{"tampered ciphertext", patch(len(good)-1, good[len(good)-1]^1), "correct horse battery", ErrWrongPassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v")
			os.WriteFile(path, tc.file, 0o600)
			if _, _, err := Open(path, tc.pw); !errors.Is(err, tc.want) {
				t.Fatalf("Open = %v, want %v", err, tc.want)
			}
		})
	}
	if _, _, err := Open(filepath.Join(t.TempDir(), "missing"), "x"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Open(missing) = %v, want fs.ErrNotExist", err)
	}
}

func TestSchemaVersion(t *testing.T) {
	cheapKDF(t)
	for _, tc := range []struct {
		version int
		want    error
	}{{5, ErrNewerVault}, {3, ErrFormat}} {
		path := filepath.Join(t.TempDir(), "v")
		s, _, err := Create(path, "correct horse battery", false)
		if err != nil {
			t.Fatal(err)
		}
		plain, _ := json.Marshal(Data{Version: tc.version})
		b, _ := seal(s.key, s.salt, s.kdf, plain)
		s.Close()
		os.WriteFile(path, b, 0o600)
		if _, _, err := Open(path, "correct horse battery"); !errors.Is(err, tc.want) {
			t.Errorf("schema %d: Open = %v, want %v", tc.version, err, tc.want)
		}
	}
}

func TestCreate(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "sub", "v")
	if _, _, err := Create(path, "short", false); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password: %v", err)
	}
	s, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if d.Version != schemaVersion || len(d.Folders) != 1 || d.Folders[0].ID != DefaultFolderID {
		t.Fatalf("Create returned %+v", d)
	}
	if _, _, err := Create(path, "correct horse battery", false); !errors.Is(err, ErrExists) {
		t.Fatalf("existing file: %v", err)
	}
	s, _, err = Create(path, "another long password", true)
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	s.Close()
	if _, _, err := Open(path, "another long password"); err != nil {
		t.Fatalf("open overwritten vault: %v", err)
	}
	if _, _, err := Create(filepath.Dir(path), "correct horse battery", true); !errors.Is(err, ErrIsDir) {
		t.Fatalf("folder: %v, want ErrIsDir", err)
	}
}

// TestPasswordNormalization opens a vault with a canonically equivalent
// password: "ü" as one character or as "u" plus a combining diaeresis.
func TestPasswordNormalization(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	s, _, err := Create(path, "grüße aus köln", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, _, err = Open(path, "grüße aus köln")
	if err != nil {
		t.Fatalf("decomposed password: %v", err)
	}
	s.Close()
}

func TestWeakerThan(t *testing.T) {
	def := kdfParams{time: 3, memory: 256 << 10, threads: 4}
	tests := []struct {
		name string
		p    kdfParams
		want bool
	}{
		{"less memory", kdfParams{time: 3, memory: 64 << 10, threads: 4}, true},
		{"fewer passes", kdfParams{time: 2, memory: 256 << 10, threads: 4}, true},
		{"equal", def, false},
		{"more memory, fewer passes", kdfParams{time: 1, memory: 2 << 20, threads: 4}, false},
		{"more passes, less memory", kdfParams{time: 4, memory: 128 << 10, threads: 4}, false},
	}
	for _, tt := range tests {
		if got := tt.p.weakerThan(def); got != tt.want {
			t.Errorf("%s: weakerThan = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	s, _, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	want := fixtureData(t)
	if err := s.Snapshot(want); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, got, err := Open(path, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip =\n%+v\nwant\n%+v", got, want)
	}
}

func TestNewestSnapshotWins(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	s, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d.PutFolder(Folder{Name: "first"})
	s.Snapshot(d)
	d.PutFolder(Folder{Name: "second"})
	s.Snapshot(d)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := reopen(t, path); len(got.Folders) != 3 {
		t.Fatalf("Flush did not write the newest snapshot: %+v", got.Folders)
	}
}

// TestSnapshotDuringWrite checks that a snapshot, taken on the UI goroutine,
// does not wait for a write in progress, which can be slow on a network share.
func TestSnapshotDuringWrite(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	s, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d.PutFolder(Folder{Name: "added"})

	s.mu.Lock() // a write in progress
	done := make(chan error, 1)
	go func() { done <- s.Snapshot(d) }()
	select {
	case err = <-done:
		s.mu.Unlock()
	case <-time.After(5 * time.Second):
		s.mu.Unlock()
		t.Fatal("Snapshot waits for the write in progress")
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := reopen(t, path); len(got.Folders) != 2 {
		t.Fatalf("snapshot not written: %+v", got.Folders)
	}
}

func TestExternalModification(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	a, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, _, err := Open(path, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	b.Snapshot(d)
	if err := b.Flush(); err != nil {
		t.Fatal(err)
	}
	a.Snapshot(d)
	if err := a.Flush(); !errors.Is(err, ErrModified) {
		t.Fatalf("write after another store saved: %v, want ErrModified", err)
	}
}

func TestFlushNeverCreatesDirectories(t *testing.T) {
	cheapKDF(t)
	dir := filepath.Join(t.TempDir(), "share")
	path := filepath.Join(dir, "v")
	s, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	os.RemoveAll(dir) // e.g. a network share that went away
	s.Snapshot(d)
	if err := s.Flush(); err == nil {
		t.Fatal("Flush succeeded although the directory is gone")
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("Flush recreated the directory")
	}
}

func TestChangePassword(t *testing.T) {
	cheapKDF(t)
	path := filepath.Join(t.TempDir(), "v")
	s, d, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	d.PutFolder(Folder{Name: "kept"})
	s.Snapshot(d) // pending, written by ChangePassword

	if err := s.ChangePassword("wrong password!!", "new long password"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong current password: %v", err)
	}
	if err := s.ChangePassword("correct horse battery", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak new password: %v", err)
	}
	if err := s.ChangePassword("correct horse battery", "new long password"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(path, "correct horse battery"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("old password still opens the vault: %v", err)
	}
	if got := reopenWith(t, path, "new long password"); len(got.Folders) != 2 {
		t.Fatalf("pending change lost: %+v", got.Folders)
	}

	// Saves after the change use the new key.
	d.PutFolder(Folder{Name: "after"})
	s.Snapshot(d)
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := reopenWith(t, path, "new long password"); len(got.Folders) != 3 {
		t.Fatalf("save after password change: %+v", got.Folders)
	}
}

// TestClosedStore checks that a closed store reports changes it never wrote,
// e.g. when the program ends while a vault is locked whose last save failed.
func TestClosedStore(t *testing.T) {
	cheapKDF(t)
	s, d, err := Create(filepath.Join(t.TempDir(), "v"), "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush on a closed store without changes: %v", err)
	}
	s.Snapshot(d)
	if err := s.Flush(); !errors.Is(err, errUnsaved) {
		t.Fatalf("Flush on a closed store with a change: %v, want errUnsaved", err)
	}
}

// TestUpgradeNotWritten opens a vault with weak key derivation settings that
// cannot be upgraded, here because it is read-only.
func TestUpgradeNotWritten(t *testing.T) {
	cheapKDF(t)
	dir := filepath.Join(t.TempDir(), "ro")
	path := filepath.Join(dir, "v")
	s, _, err := Create(path, "correct horse battery", false)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	defaultKDF.time++ // the vault is weaker than the default now
	writable := func() {
		os.Chmod(dir, 0o700)
		os.Chmod(path, 0o600)
	}
	t.Cleanup(writable)
	os.Chmod(path, 0o400) // Windows refuses to replace it
	os.Chmod(dir, 0o500)  // Unix refuses to create the temporary file
	before, _ := os.ReadFile(path)

	s, d, err := Open(path, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Skip("the read-only vault was written, e.g. by root")
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush without changes: %v", err)
	}
	writable()
	if err := s.ChangePassword("correct horse battery", "new long password"); err != nil {
		t.Fatal(err)
	}
	if got := reopenWith(t, path, "new long password"); !reflect.DeepEqual(got, d) {
		t.Fatalf("after the password change: %+v, want %+v", got, d)
	}
}

func reopen(t *testing.T, path string) Data { return reopenWith(t, path, "correct horse battery") }

func reopenWith(t *testing.T, path, pw string) Data {
	t.Helper()
	s, d, err := Open(path, pw)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	return d
}
