// Package vault stores SSH hosts, key profiles and trusted host keys in an
// encrypted file.
package vault

import (
	"crypto/rand"
	"errors"
	"slices"
	"strings"
)

// DefaultFolderID is the folder that always exists and cannot be deleted.
const DefaultFolderID = "default"

// Host authentication methods.
const (
	AuthPassword = "password"
	AuthKey      = "key"
)

// Key profile sources. An empty source counts as KeySourceVault.
const (
	KeySourceVault = "vault" // key embedded in the vault
	KeySourceFile  = "file"  // key file on disk, only the path is stored
)

var (
	ErrDefaultFolder = errors.New("the default folder cannot be deleted")
	ErrProfileInUse  = errors.New("key profile is in use")
	ErrNotFound      = errors.New("not found")
)

// Data is the decrypted content of a vault.
type Data struct {
	Version     int          `json:"version"`
	Folders     []Folder     `json:"folders,omitempty"`
	KeyProfiles []KeyProfile `json:"key_profiles,omitempty"`
	KnownHosts  []KnownHost  `json:"known_hosts,omitempty"`
	Hosts       []Host       `json:"hosts"`
}

type Folder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Host struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Hostname     string `json:"host"`
	Port         int    `json:"port"`
	User         string `json:"username"`
	Auth         string `json:"auth"`
	FolderID     string `json:"folder_id,omitempty"`
	KeyProfileID string `json:"key_profile_id,omitempty"`
	// Password is the login password for password auth. With key auth it is
	// optional and only used for pasting during a session (e.g. sudo).
	Password string `json:"password,omitempty"`
}

type KeyProfile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Source      string `json:"source,omitempty"`
	Key         string `json:"private_key,omitempty"`
	Passphrase  string `json:"private_key_passphrase,omitempty"`
	KeyType     string `json:"key_type,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Path        string `json:"private_key_path,omitempty"` // file source only
}

// KnownHost is a trusted SSH host key. Host is in known_hosts address form
// ("example.com" or "[example.com]:2222"), Key in authorized_keys form.
type KnownHost struct {
	Host string `json:"host"`
	Key  string `json:"key"`
}

// New returns the content of an empty vault.
func New() Data {
	return Data{
		Version: schemaVersion,
		Folders: []Folder{{ID: DefaultFolderID, Name: "General"}},
		Hosts:   []Host{},
	}
}

func (d Data) Folder(id string) (Folder, bool) {
	return find(d.Folders, id, func(f Folder) string { return f.ID })
}
func (d Data) Host(id string) (Host, bool) {
	return find(d.Hosts, id, func(h Host) string { return h.ID })
}
func (d Data) Profile(id string) (KeyProfile, bool) {
	return find(d.KeyProfiles, id, func(p KeyProfile) string { return p.ID })
}

// FolderSize returns the number of hosts in a folder.
func (d Data) FolderSize(id string) int {
	return count(d.Hosts, func(h Host) bool { return h.FolderID == id })
}

// ProfileUsage returns the number of hosts using a key profile.
func (d Data) ProfileUsage(id string) int {
	return count(d.Hosts, func(h Host) bool { return h.KeyProfileID == id })
}

// PutFolder adds f (empty ID) or replaces the folder with the same ID.
func (d *Data) PutFolder(f Folder) string {
	return put(&d.Folders, f, func(f *Folder) *string { return &f.ID })
}

// DeleteFolder removes a folder and moves its hosts to the default folder.
func (d *Data) DeleteFolder(id string) error {
	if id == DefaultFolderID {
		return ErrDefaultFolder
	}
	for i := range d.Hosts {
		if d.Hosts[i].FolderID == id {
			d.Hosts[i].FolderID = DefaultFolderID
		}
	}
	d.Folders = slices.DeleteFunc(d.Folders, func(f Folder) bool { return f.ID == id })
	return nil
}

// PutHost adds h (empty ID) or replaces the host with the same ID.
func (d *Data) PutHost(h Host) string {
	return put(&d.Hosts, h, func(h *Host) *string { return &h.ID })
}

func (d *Data) DeleteHost(id string) {
	d.Hosts = slices.DeleteFunc(d.Hosts, func(h Host) bool { return h.ID == id })
}

// MoveHost puts a host into another folder.
func (d *Data) MoveHost(id, folderID string) error {
	if _, ok := d.Folder(folderID); !ok {
		return ErrNotFound
	}
	for i := range d.Hosts {
		if d.Hosts[i].ID == id {
			d.Hosts[i].FolderID = folderID
			return nil
		}
	}
	return ErrNotFound
}

// PutProfile adds p (empty ID) or replaces the profile with the same ID.
func (d *Data) PutProfile(p KeyProfile) string {
	return put(&d.KeyProfiles, p, func(p *KeyProfile) *string { return &p.ID })
}

// DeleteProfile removes a key profile that no host uses.
func (d *Data) DeleteProfile(id string) error {
	if d.ProfileUsage(id) > 0 {
		return ErrProfileInUse
	}
	d.KeyProfiles = slices.DeleteFunc(d.KeyProfiles, func(p KeyProfile) bool { return p.ID == id })
	return nil
}

// Trust makes key the only trusted key of host. Host names compare
// case-insensitively, like in OpenSSH.
func (d *Data) Trust(host, key string) {
	d.KnownHosts = slices.DeleteFunc(d.KnownHosts, func(k KnownHost) bool { return strings.EqualFold(k.Host, host) })
	d.KnownHosts = append(d.KnownHosts, KnownHost{Host: host, Key: key})
}

// IsFile reports whether the key is read from a file instead of the vault.
func (p KeyProfile) IsFile() bool { return p.Source == KeySourceFile }

// normalize guarantees the default folder and that every host is in an
// existing folder.
func (d *Data) normalize() {
	if _, ok := d.Folder(DefaultFolderID); !ok {
		d.Folders = append([]Folder{{ID: DefaultFolderID, Name: "General"}}, d.Folders...)
	}
	for i := range d.Hosts {
		if _, ok := d.Folder(d.Hosts[i].FolderID); !ok {
			d.Hosts[i].FolderID = DefaultFolderID
		}
	}
	if d.Hosts == nil {
		d.Hosts = []Host{}
	}
}

func find[T any](items []T, id string, key func(T) string) (T, bool) {
	for _, it := range items {
		if key(it) == id {
			return it, true
		}
	}
	var zero T
	return zero, false
}

func count[T any](items []T, match func(T) bool) int {
	n := 0
	for _, it := range items {
		if match(it) {
			n++
		}
	}
	return n
}

func put[T any](items *[]T, item T, id func(*T) *string) string {
	p := id(&item)
	if *p == "" {
		*p = rand.Text()
		*items = append(*items, item)
		return *p
	}
	for i := range *items {
		if *id(&(*items)[i]) == *p {
			(*items)[i] = item
			return *p
		}
	}
	*items = append(*items, item)
	return *p
}
