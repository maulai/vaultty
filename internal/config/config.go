// Package config holds the machine-local settings: which vault to open,
// recently used vaults and the auto-lock timeout.
package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/maulai/vaultty/internal/atomicfile"
)

const (
	appName         = "vaultty"
	defaultAutoLock = 3 * time.Minute
	maxRecent       = 8
)

type Config struct {
	VaultPath       string   `json:"vault_path"`
	AutoLockMinutes int      `json:"auto_lock_minutes"` // 0 = default, negative = off
	RecentVaults    []string `json:"recent_vaults,omitempty"`

	path string
}

// Load reads the config from the user config directory. A missing file means
// first run: defaults are returned and nothing is written yet.
func Load() (cfg *Config, firstRun bool, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, false, err
	}
	return load(filepath.Join(dir, appName, "config.json"))
}

func load(path string) (*Config, bool, error) {
	c := &Config{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		c.VaultPath = filepath.Join(filepath.Dir(path), "vault.enc")
		return c, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, false, err
	}
	return c, false, nil
}

// Save writes the config atomically.
func (c *Config) Save() error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return atomicfile.WriteFile(c.path, b, 0o600)
}

// SaveRemembered saves the config with path as the current vault. It starts
// from the file on disk, so that edits made while the program runs are kept.
func (c *Config) SaveRemembered(path string) error {
	fresh, _, err := load(c.path)
	if err != nil {
		fresh = c
	}
	fresh.Remember(path)
	return fresh.Save()
}

// AutoLock returns the inactivity timeout; zero means off.
func (c *Config) AutoLock() time.Duration {
	switch {
	case c.AutoLockMinutes < 0:
		return 0
	case c.AutoLockMinutes == 0:
		return defaultAutoLock
	}
	return time.Duration(c.AutoLockMinutes) * time.Minute
}

// Remember makes path the current vault and moves it to the front of the
// recently used list.
func (c *Config) Remember(path string) {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	c.VaultPath = path
	recent := []string{path}
	for _, p := range c.RecentVaults {
		if p != path && len(recent) < maxRecent {
			recent = append(recent, p)
		}
	}
	c.RecentVaults = recent
}

// Recent returns the current vault followed by the recently used ones.
func (c *Config) Recent() []string {
	var out []string
	for _, p := range append([]string{c.VaultPath}, c.RecentVaults...) {
		if p != "" && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}
