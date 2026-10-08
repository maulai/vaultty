package vault

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const maxKeyFile = 64 << 10

var (
	ErrNoKey       = errors.New("key profile has no key")
	ErrKeyTooLarge = errors.New("key file too large")
)

// ExpandPath trims spaces and surrounding quotes (as added by "copy as path")
// and expands a leading ~ to the home directory.
func ExpandPath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	return p
}

// PortablePath returns p as an absolute path, written as "~/..." when it is
// inside the home directory, so the same profile works on every machine with
// the same layout.
func PortablePath(p string) string {
	abs, err := filepath.Abs(ExpandPath(p))
	if err != nil {
		return p
	}
	if home, err := os.UserHomeDir(); err == nil {
		rel, err := filepath.Rel(home, abs)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return abs
}

// ResolvePath turns a stored path into a path for this machine.
func ResolvePath(p string) string {
	return filepath.Clean(filepath.FromSlash(ExpandPath(p)))
}

// ReadKey returns the profile's private key: embedded, or read from its file.
func (p KeyProfile) ReadKey() ([]byte, error) {
	if !p.IsFile() {
		if p.Key == "" {
			return nil, ErrNoKey
		}
		return []byte(p.Key), nil
	}
	f, err := os.Open(ResolvePath(p.Path))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFile {
		return nil, ErrKeyTooLarge
	}
	return b, nil
}
