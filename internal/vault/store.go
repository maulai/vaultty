package vault

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"unicode/utf8"

	"github.com/maulai/vaultty/internal/atomicfile"
)

const minPasswordLen = 12

var (
	ErrExists       = errors.New("vault file already exists")
	ErrIsDir        = errors.New("vault path is a folder")
	ErrModified     = errors.New("vault file was changed by another program")
	ErrWeakPassword = fmt.Errorf("password needs at least %d characters", minPasswordLen)
	errClosed       = errors.New("vault is closed")
	errUnsaved      = errors.New("vault was locked with changes that could not be saved")
)

// Store is an open vault file. It holds the derived key, never the password,
// and serializes writes so that the newest snapshot always wins.
type Store struct {
	path string

	mu      sync.Mutex // held during file I/O
	key     []byte
	salt    []byte
	kdf     kdfParams
	sum     [sha256.Size]byte // hash of the file as last read or written
	written uint64            // newest snapshot on disk

	snapMu  sync.Mutex // guards seq and pending; never held during I/O
	seq     uint64     // last snapshot number handed out
	pending *snapshot  // newest snapshot, written or not
}

// snapshot is vault content captured at one point in time.
type snapshot struct {
	seq   uint64
	plain []byte
}

// Create writes a new, empty vault. An existing file is only replaced when
// overwrite is set.
func Create(path, password string, overwrite bool) (*Store, Data, error) {
	if utf8.RuneCountInString(password) < minPasswordLen {
		return nil, Data{}, ErrWeakPassword
	}
	switch fi, err := os.Stat(path); {
	case err == nil && fi.IsDir():
		return nil, Data{}, ErrIsDir
	case err == nil && !overwrite:
		return nil, Data{}, ErrExists
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, Data{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, Data{}, err
	}
	s := &Store{path: path}
	s.rekey(password)
	d := New()
	err := s.Snapshot(d)
	if err == nil {
		s.mu.Lock()
		err = s.flush(false)
		s.mu.Unlock()
	}
	if err != nil {
		s.Close()
		return nil, Data{}, err
	}
	return s, d, nil
}

// Open decrypts the vault at path. Files with weaker key derivation settings
// than the current default are re-encrypted with the default right away.
func Open(path, password string) (*Store, Data, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, Data{}, err
	}
	h, ciphertext, err := parse(b)
	if err != nil {
		return nil, Data{}, err
	}
	key := deriveKey(password, h.salt, h.kdf)
	plain, err := decrypt(key, h, ciphertext)
	if err != nil {
		clear(key)
		return nil, Data{}, err
	}
	defer clear(plain)
	d, err := decode(plain)
	if err != nil {
		clear(key)
		return nil, Data{}, err
	}
	s := &Store{path: path, key: key, salt: append([]byte(nil), h.salt...), kdf: h.kdf, sum: sha256.Sum256(b)}
	if h.kdf.weakerThan(defaultKDF) {
		// If this fails, e.g. for a read-only file, the store keeps the old
		// key; the upgrade is tried again on the next open.
		_ = s.reseal(password, plain)
	}
	return s, d, nil
}

func decode(plain []byte) (Data, error) {
	var d Data
	if err := json.Unmarshal(plain, &d); err != nil {
		return Data{}, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	switch {
	case d.Version > schemaVersion:
		return Data{}, ErrNewerVault
	case d.Version != schemaVersion:
		return Data{}, ErrFormat
	}
	d.normalize()
	return d, nil
}

// Path returns the vault file path.
func (s *Store) Path() string { return s.path }

// Snapshot captures d for the next Flush. Call it synchronously when the data
// changes; snapshots taken later win over earlier ones. It does not wait for
// a write in progress.
func (s *Store) Snapshot(d Data) error {
	d.Version = schemaVersion
	plain, err := json.Marshal(d)
	if err != nil {
		return err
	}
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	s.seq++
	s.pending = &snapshot{seq: s.seq, plain: plain}
	return nil
}

// Flush writes the newest snapshot unless it is on disk already. It refuses
// with ErrModified when the file changed since this store last read or wrote
// it. On a closed store, a snapshot that was never written is an error.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flush(true)
}

// flush is Flush with s.mu held. check enables the ErrModified check.
func (s *Store) flush(check bool) error {
	s.snapMu.Lock()
	sn := s.pending
	s.snapMu.Unlock()
	switch {
	case sn == nil || sn.seq <= s.written:
		return nil
	case s.key == nil:
		return errUnsaved
	}
	if check {
		if _, err := s.readUnchanged(); err != nil {
			return err
		}
	}
	b, err := seal(s.key, s.salt, s.kdf, sn.plain)
	if err != nil {
		return err
	}
	if err := atomicfile.WriteFile(s.path, b, 0o600); err != nil {
		return err
	}
	s.sum = sha256.Sum256(b)
	s.written = sn.seq
	clear(sn.plain)
	return nil
}

// readUnchanged reads the file. It reports ErrModified when the file differs
// from what this store last read or wrote, e.g. after another machine saved
// the same vault.
func (s *Store) readUnchanged() ([]byte, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(b) != s.sum {
		return nil, ErrModified
	}
	return b, nil
}

// ChangePassword re-encrypts the vault with a key derived from next. The new
// key is used only after the file was written successfully.
func (s *Store) ChangePassword(current, next string) error {
	if utf8.RuneCountInString(next) < minPasswordLen {
		return ErrWeakPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return errClosed
	}
	check := deriveKey(current, s.salt, s.kdf)
	ok := subtle.ConstantTimeCompare(check, s.key) == 1
	clear(check)
	if !ok {
		return ErrWrongPassword
	}
	if err := s.flush(true); err != nil {
		return err
	}
	b, err := s.readUnchanged()
	if err != nil {
		return err
	}
	h, ciphertext, err := parse(b)
	if err != nil {
		return err
	}
	plain, err := decrypt(s.key, h, ciphertext)
	if err != nil {
		return err
	}
	defer clear(plain)
	return s.reseal(next, plain)
}

// reseal replaces the file with plain, encrypted with a key derived from
// password with the default settings and a fresh salt. The store keeps its
// old key unless the file was written. s.mu must be held or s not shared yet.
func (s *Store) reseal(password string, plain []byte) error {
	oldKey, oldSalt, oldKDF := s.key, s.salt, s.kdf
	s.key = nil
	s.rekey(password)
	out, err := seal(s.key, s.salt, s.kdf, plain)
	if err == nil {
		_, err = s.readUnchanged() // it may have changed during the key derivation
	}
	if err == nil {
		err = atomicfile.WriteFile(s.path, out, 0o600)
	}
	if err != nil {
		clear(s.key)
		s.key, s.salt, s.kdf = oldKey, oldSalt, oldKDF
		return err
	}
	clear(oldKey)
	s.sum = sha256.Sum256(out)
	return nil
}

// Close wipes the key. Later writes fail.
func (s *Store) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.key)
	s.key = nil
}

// rekey derives a new key with the default settings and a fresh salt.
func (s *Store) rekey(password string) {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	clear(s.key)
	s.key, s.salt, s.kdf = deriveKey(password, salt, defaultKDF), salt, defaultKDF
}
