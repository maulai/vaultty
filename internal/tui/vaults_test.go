package tui

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/config"
	"github.com/maulai/vaultty/internal/vault"
)

func TestCreateVault(t *testing.T) {
	m := unlocked(t)
	if _, ok := m.v.data.Folder(vault.DefaultFolderID); !ok {
		t.Fatal("no default folder")
	}
	path := m.v.store.Path()
	st, d, err := vault.Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, ok := d.Folder(vault.DefaultFolderID); !ok || d.Version != 4 {
		t.Errorf("vault on disk: version %d, default folder %v", d.Version, ok)
	}
	cfg, firstRun, err := config.Load()
	if err != nil || firstRun || cfg.VaultPath != path {
		t.Errorf("config: vault %q, first run %v, err %v; want %q remembered", cfg.VaultPath, firstRun, err, path)
	}
}

func TestCreateValidation(t *testing.T) {
	m := newTestModel(testConfig(t), true)
	press(m, "tab", testPassword, "tab", "something else")
	if press(m, "enter") != nil || !m.status.err || !m.idle() {
		t.Fatal("mismatching passwords were accepted")
	}

	m.showCreate(filepath.Join(t.TempDir(), "v.vault"))
	press(m, "tab", "short", "tab", "short")
	msg := press(m, "enter")().(openedMsg)
	if !errors.Is(msg.err, vault.ErrWeakPassword) {
		t.Fatalf("weak password: %v", msg.err)
	}
	send(m, msg)
	if m.v != nil || m.screen != scrCreate || !m.status.err {
		t.Fatal("a weak password did not keep the create screen")
	}
}

// TestCreateFolderPath checks that a folder as the path of a new vault, e.g.
// the prefilled folder without a file name, never leads to the question
// whether to overwrite it.
func TestCreateFolderPath(t *testing.T) {
	m := newTestModel(testConfig(t), true)
	dir := t.TempDir()
	for _, path := range []string{dir + string(filepath.Separator), dir} {
		m.showCreate(path)
		press(m, "tab", testPassword, "tab", testPassword)
		run(m, press(m, "enter"))
		if m.screen != scrCreate || m.v != nil || !m.status.err {
			t.Errorf("path %q: screen %d, status %+v", path, m.screen, m.status)
		}
	}
}

// TestSurrogatePairs types a password the way a Windows console delivers it:
// one key event per UTF-16 code unit.
func TestSurrogatePairs(t *testing.T) {
	m := newTestModel(testConfig(t), true)
	const want = "correct horse 🐴🔋📎"
	units := utf16.Encode([]rune(want))
	units = append([]uint16{0xdc00}, units...) // a low surrogate without its high half
	units = append(units, 0xd83d, 'x', 0xd83d) // a high surrogate without its low half
	press(m, "tab")
	for _, u := range units {
		send(m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{rune(u)}})
	}
	if got := m.create.value(createPassword); got != want+"x" {
		t.Fatalf("password %q, want %q", got, want+"x")
	}
}

func TestCreateOverwrite(t *testing.T) {
	m := newTestModel(testConfig(t), true)
	path := m.create.value(createPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	press(m, "tab", testPassword, "tab", testPassword)
	run(m, press(m, "enter"))
	if m.screen != scrConfirm || m.v != nil || m.status != (status{}) {
		t.Fatalf("no overwrite question: screen %d, status %+v", m.screen, m.status)
	}
	if press(m, "enter") != nil || m.screen != scrConfirm {
		t.Fatal("enter overwrote the file")
	}
	run(m, press(m, "y"))
	if m.v == nil {
		t.Fatalf("not created: %q", m.status.text)
	}
	if _, _, err := vault.Open(path, testPassword); err != nil {
		t.Fatal(err)
	}
}

func TestUnlock(t *testing.T) {
	cfg := testConfig(t)
	st, _, err := vault.Create(cfg.VaultPath, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	m := newTestModel(cfg, false)
	if m.screen != scrUnlock {
		t.Fatalf("screen %d, want unlock", m.screen)
	}

	press(m, "wrong password")
	cmd := press(m, "enter")
	if press(m, "enter") != nil {
		t.Fatal("a repeated enter started another unlock")
	}
	msg := cmd().(openedMsg)
	if !errors.Is(msg.err, vault.ErrWrongPassword) {
		t.Fatalf("wrong password: %v", msg.err)
	}
	send(m, msg)
	if m.v != nil || !m.status.err || m.unlock.value(0) != "" {
		t.Fatal("a wrong password was not rejected or stays in the input")
	}

	// Only a connect can be cancelled; esc does not abandon the unlock.
	press(m, testPassword)
	cmd = press(m, "enter")
	press(m, "esc")
	run(m, cmd)
	if m.v == nil || m.screen != scrFolders || m.unlock != nil {
		t.Fatalf("not unlocked: %q", m.status.text)
	}
	if m.status != (status{}) {
		t.Errorf("status %+v after unlocking", m.status)
	}
}

// TestPasswordNotKept checks that no copy of the model keeps a typed master
// password once the vault is open: the program holds on to its initial
// model, which shares the forms.
func TestPasswordNotKept(t *testing.T) {
	cfg := testConfig(t)
	st, _, err := vault.Create(cfg.VaultPath, testPassword, false)
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	m := newTestModel(cfg, false)
	initial := *m
	press(m, "wrong password")
	run(m, press(m, "enter"))
	press(m, testPassword)
	run(m, press(m, "enter"))
	if m.v == nil {
		t.Fatalf("not unlocked: %q", m.status.text)
	}
	if initial.unlock.value(0) != "" {
		t.Error("the unlock form keeps a password")
	}

	m = newTestModel(testConfig(t), true)
	initial = *m
	press(m, "tab", testPassword, "tab", testPassword)
	run(m, press(m, "enter"))
	if m.v == nil {
		t.Fatalf("not created: %q", m.status.text)
	}
	if initial.create.value(createPassword) != "" || initial.create.value(createRepeat) != "" {
		t.Error("the create form keeps the password")
	}
}

func TestChangePassword(t *testing.T) {
	m := unlocked(t)
	const next = "a new master password"
	press(m, "c", "not the password", "tab", next, "tab", next)
	cmd := press(m, "enter")
	msg := cmd().(passwordChangedMsg)
	if !errors.Is(msg.err, vault.ErrWrongPassword) {
		t.Fatalf("wrong current password: %v", msg.err)
	}
	send(m, msg)
	if m.screen != scrPassword || !m.status.err {
		t.Fatal("a wrong current password was accepted")
	}

	press(m, "up", "up", "ctrl+u", testPassword)
	run(m, press(m, "enter"))
	if m.screen != scrFolders || m.v.passwordForm != nil || m.status.err {
		t.Fatalf("password not changed: %q", m.status.text)
	}
	if _, _, err := vault.Open(m.v.store.Path(), next); err != nil {
		t.Fatal(err)
	}
}
