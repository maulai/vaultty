package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestAutoLock(t *testing.T) {
	for _, tc := range []struct {
		minutes int
		want    time.Duration
	}{
		{0, 3 * time.Minute},
		{-1, 0},
		{5, 5 * time.Minute},
	} {
		c := Config{AutoLockMinutes: tc.minutes}
		if got := c.AutoLock(); got != tc.want {
			t.Errorf("AutoLock(%d) = %v, want %v", tc.minutes, got, tc.want)
		}
	}
}

func TestRemember(t *testing.T) {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }

	c := Config{}
	for _, n := range []string{"a", "b", "a", "c", "d", "e", "f", "g", "h", "i"} {
		c.Remember(p(n))
	}
	if c.VaultPath != p("i") {
		t.Fatalf("VaultPath = %q, want %q", c.VaultPath, p("i"))
	}
	want := []string{p("i"), p("h"), p("g"), p("f"), p("e"), p("d"), p("c"), p("a")}
	if !slices.Equal(c.RecentVaults, want) {
		t.Fatalf("RecentVaults = %q, want %q", c.RecentVaults, want)
	}
	if got := c.Recent(); !slices.Equal(got, want) {
		t.Fatalf("Recent() = %q, want %q", got, want)
	}

	c.Remember("relative.enc")
	if !filepath.IsAbs(c.VaultPath) {
		t.Fatalf("Remember stored a relative path: %q", c.VaultPath)
	}
}

func TestLoadSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vaultty", "config.json")

	c, first, err := load(path)
	if err != nil || !first {
		t.Fatalf("load(missing) = first %v, err %v; want first run", first, err)
	}
	if c.VaultPath != filepath.Join(filepath.Dir(path), "vault.enc") {
		t.Fatalf("default VaultPath = %q", c.VaultPath)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("first run must not write the config")
	}

	c.AutoLockMinutes = 7
	c.Remember(filepath.Join(t.TempDir(), "v.enc"))
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	got, first, err := load(path)
	if err != nil || first {
		t.Fatalf("load(saved) = first %v, err %v", first, err)
	}
	if got.VaultPath != c.VaultPath || got.AutoLockMinutes != 7 || !slices.Equal(got.RecentVaults, c.RecentVaults) {
		t.Fatalf("round trip = %+v, want %+v", got, c)
	}
}

// TestSaveRememberedKeepsEdits checks that recording the current vault keeps
// what the user or another instance wrote to the file meanwhile.
func TestSaveRememberedKeepsEdits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	running := &Config{path: path}
	running.Remember(filepath.Join(dir, "a.enc"))
	if err := running.Save(); err != nil {
		t.Fatal(err)
	}

	edited := *running
	edited.AutoLockMinutes = 30
	edited.Remember(filepath.Join(dir, "b.enc"))
	if err := edited.Save(); err != nil {
		t.Fatal(err)
	}

	c := filepath.Join(dir, "c.enc")
	if err := running.SaveRemembered(c); err != nil {
		t.Fatal(err)
	}
	got, _, err := load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{c, filepath.Join(dir, "b.enc"), filepath.Join(dir, "a.enc")}
	if got.AutoLockMinutes != 30 || got.VaultPath != c || !slices.Equal(got.RecentVaults, want) {
		t.Fatalf("saved %+v, want auto lock 30 and recent vaults %q", got, want)
	}
}

func TestLoadDamaged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, first, err := load(path); err == nil || first {
		t.Fatalf("load(damaged) = first %v, err %v; want an error and no first run", first, err)
	}
}
