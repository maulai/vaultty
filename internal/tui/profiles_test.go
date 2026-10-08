package tui

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
	"golang.org/x/crypto/ssh"
)

// writeKey writes a new ed25519 private key, encrypted when passphrase is set.
func writeKey(t *testing.T, passphrase string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "id_test")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// saveProfile submits the profile form, runs the key check and returns the
// stored profile.
func saveProfile(t *testing.T, m *model) vault.KeyProfile {
	t.Helper()
	id := m.v.profileForm.id
	run(m, press(m, "enter"))
	if m.screen == scrProfileForm || m.status.err {
		t.Fatalf("profile not saved: %q", m.status.text)
	}
	if id == "" {
		id = m.v.data.KeyProfiles[len(m.v.data.KeyProfiles)-1].ID
	}
	p, _ := m.v.data.Profile(id)
	return p
}

// editProfile opens the form of a stored profile.
func editProfile(m *model, id string) {
	m.screen = scrProfiles
	m.v.profileCursor = slices.IndexFunc(m.v.data.KeyProfiles, func(p vault.KeyProfile) bool { return p.ID == id })
	press(m, "e")
}

func TestProfileForm(t *testing.T) {
	m := unlocked(t)
	key := writeKey(t, "")
	press(m, "p")

	// In vault: the key is embedded; the name defaults to the file name.
	press(m, "n", "tab", "tab", key)
	embedded := saveProfile(t, m)
	if embedded.IsFile() || embedded.Key == "" || embedded.Path != "" || embedded.KeyType != ssh.KeyAlgoED25519 ||
		embedded.Name != "id_test" {
		t.Fatalf("embedded profile %+v", embedded)
	}

	// File: only the path is stored.
	press(m, "n", "tab", "right", "tab", key)
	file := saveProfile(t, m)
	if !file.IsFile() || file.Key != "" || file.Path != vault.PortablePath(key) || file.Fingerprint != embedded.Fingerprint {
		t.Fatalf("file profile %+v", file)
	}

	// Editing an embedded profile with an empty key file keeps the key.
	editProfile(m, embedded.ID)
	press(m, "ctrl+u", "renamed")
	if p := saveProfile(t, m); p.Key != embedded.Key || p.Name != "renamed" {
		t.Fatalf("edited profile %+v", p)
	}

	// Switching an embedded profile to a file drops the key from the vault.
	// Space switches the source like right.
	editProfile(m, embedded.ID)
	press(m, "tab", " ", "tab", key)
	if p := saveProfile(t, m); !p.IsFile() || p.Key != "" || p.Path != file.Path {
		t.Fatalf("switched to file: %+v", p)
	}

	// Switching a file profile to the vault imports its file.
	editProfile(m, file.ID)
	press(m, "tab", "left")
	if p := saveProfile(t, m); p.IsFile() || p.Key == "" || p.Path != "" {
		t.Fatalf("switched to vault: %+v", p)
	}
}

func TestProfileWrongPassphrase(t *testing.T) {
	m := unlocked(t)
	key := writeKey(t, "secret")
	press(m, "p", "n", "tab", "tab", key, "tab", "wrong")
	msg := press(m, "enter")().(keyCheckedMsg)
	if !errors.Is(msg.err, sshclient.ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", msg.err)
	}
	send(m, msg)
	if m.screen != scrProfileForm || !m.status.err || len(m.v.data.KeyProfiles) != 0 {
		t.Fatal("a key with a wrong passphrase was accepted")
	}
	press(m, "ctrl+u", "secret")
	if p := saveProfile(t, m); p.Passphrase != "secret" || p.KeyType == "" {
		t.Fatalf("profile %+v", p)
	}
}

func TestProfileMissingFile(t *testing.T) {
	m := unlocked(t)
	key := writeKey(t, "")
	press(m, "p", "n", "tab", "right", "tab", key)
	p := saveProfile(t, m)
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}

	// The unchanged path may be on another computer: accepted unchecked.
	editProfile(m, p.ID)
	if got := saveProfile(t, m); got.Path != p.Path || got.Fingerprint != p.Fingerprint {
		t.Fatalf("unchanged path: %+v", got)
	}

	// A changed path must name a key file here.
	editProfile(m, p.ID)
	press(m, "tab", "tab", "ctrl+u", key+".missing")
	msg := press(m, "enter")().(keyCheckedMsg)
	if !errors.Is(msg.err, fs.ErrNotExist) {
		t.Fatalf("changed path: %v", msg.err)
	}
}

func TestProfileInUse(t *testing.T) {
	m := unlocked(t)
	pid := m.v.data.PutProfile(vault.KeyProfile{Name: "deploy", Key: "key"})
	m.v.data.PutHost(vault.Host{Name: "web", Hostname: "10.0.0.1", Port: 22, User: "root", Auth: vault.AuthKey, KeyProfileID: pid})
	press(m, "p", "d")
	if m.screen != scrProfiles || !m.status.err {
		t.Fatal("a profile in use can be deleted")
	}
	if _, ok := m.v.data.Profile(pid); !ok {
		t.Fatal("profile deleted")
	}
}

func TestProfilesLock(t *testing.T) {
	m := unlocked(t)
	press(m, "p", "l")
	if m.v != nil || m.screen != scrUnlock {
		t.Fatal("l does not lock on the key profiles")
	}
}

func TestNewProfileFromHostForm(t *testing.T) {
	m := unlocked(t)
	key := writeKey(t, "")
	m.showHosts(vault.DefaultFolderID)
	// Host, user, auth key, then n on the key profile field.
	press(m, "n", "tab", "example.com", "tab", "tab", "root", "tab", "right", "tab", "n")
	if m.screen != scrProfileForm {
		t.Fatalf("screen %d, want the profile form", m.screen)
	}
	press(m, "tab", "tab", key)
	p := saveProfile(t, m)
	if m.screen != scrHostForm || m.v.hostForm.value(hostProfile) != p.ID {
		t.Fatalf("back on screen %d with profile %q, want %q", m.screen, m.v.hostForm.value(hostProfile), p.ID)
	}
	run(m, press(m, "enter"))
	i := slices.IndexFunc(m.v.data.Hosts, func(h vault.Host) bool { return h.KeyProfileID == p.ID })
	if i < 0 || m.v.data.Hosts[i].Auth != vault.AuthKey {
		t.Fatal("host not saved with the new profile")
	}
}
