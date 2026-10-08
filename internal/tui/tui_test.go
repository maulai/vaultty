package tui

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/maulai/vaultty/internal/config"
	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
)

const testPassword = "correct horse battery"

// testConfig points the user config directory to an empty temporary
// directory and loads the config from there, which makes a first run.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AppData", dir)         // Windows
	t.Setenv("XDG_CONFIG_HOME", dir) // Linux
	t.Setenv("HOME", dir)            // macOS
	cfg, firstRun, err := config.Load()
	if err != nil || !firstRun {
		t.Fatalf("config.Load: firstRun %v, err %v", firstRun, err)
	}
	return cfg
}

func newTestModel(cfg *config.Config, firstRun bool) *model {
	m := newModel(cfg, firstRun, "test")
	send(&m, tea.WindowSizeMsg{Width: 100, Height: 32})
	return &m
}

// unlocked creates a vault on the create screen and returns the model on the
// folders screen.
func unlocked(t *testing.T) *model {
	t.Helper()
	m := newTestModel(testConfig(t), true)
	press(m, "tab", testPassword, "tab", testPassword)
	run(m, press(m, "enter"))
	if m.v == nil || m.screen != scrFolders {
		t.Fatalf("not unlocked: screen %d, status %q", m.screen, m.status.text)
	}
	return m
}

// send passes messages through Update and returns the last command.
func send(m *model, msgs ...tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	for _, msg := range msgs {
		next, c := m.Update(msg)
		*m, cmd = next.(model), c
	}
	return cmd
}

// press sends keys: names like "enter" and "tab", or text to type.
func press(m *model, keys ...string) tea.Cmd {
	types := map[string]tea.KeyType{
		"enter": tea.KeyEnter, "esc": tea.KeyEsc, "tab": tea.KeyTab, "up": tea.KeyUp, "down": tea.KeyDown,
		"left": tea.KeyLeft, "right": tea.KeyRight, "ctrl+u": tea.KeyCtrlU, "backspace": tea.KeyBackspace,
	}
	var cmd tea.Cmd
	for _, k := range keys {
		msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		if t, ok := types[k]; ok {
			msg = tea.KeyMsg{Type: t}
		}
		cmd = send(m, msg)
	}
	return cmd
}

// run executes cmd and passes the resulting messages through Update, like
// the Bubble Tea runtime. Commands that dial or wait for a timer must not be
// run.
func run(m *model, cmd tea.Cmd) {
	if cmd == nil {
		return
	}
	msg := cmd()
	if batch, ok := msg.(tea.BatchMsg); ok {
		for _, c := range batch {
			run(m, c)
		}
		return
	}
	run(m, send(m, msg))
}

func addFolder(m *model, name string) string {
	return m.v.data.PutFolder(vault.Folder{Name: name})
}

func addHost(m *model, folderID, name string) string {
	return m.v.data.PutHost(vault.Host{
		Name: name, Hostname: "10.0.0.1", Port: 22, User: "root", Auth: vault.AuthPassword, FolderID: folderID,
	})
}

func TestStart(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.vault")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "unmounted", "missing.vault")

	tests := []struct {
		name     string
		path     string
		firstRun bool
		typed    string // typed into the unlock screen before the check ends
		before   screen
		after    screen // once the existence checks are done
	}{
		{"first run", filepath.Join(dir, "new.vault"), true, "", scrCreate, scrCreate},
		{"configured vault", existing, false, "", scrUnlock, scrUnlock},
		{"configured vault missing", missing, false, "", scrUnlock, scrPicker},
		{"missing while typing", missing, false, "pass", scrUnlock, scrUnlock},
		{"no vault configured", "", false, "", scrPicker, scrPicker},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := newTestModel(&config.Config{VaultPath: tt.path}, tt.firstRun)
			if m.screen != tt.before {
				t.Fatalf("screen %d, want %d", m.screen, tt.before)
			}
			if tt.typed != "" {
				press(m, tt.typed)
			}
			run(m, m.checkPaths())
			if m.screen != tt.after {
				t.Fatalf("after the checks: screen %d, want %d", m.screen, tt.after)
			}
			switch m.screen {
			case scrCreate:
				if got := m.create.value(createPath); got != tt.path {
					t.Errorf("create path %q, want %q", got, tt.path)
				}
			case scrUnlock:
				if m.unlockPath != tt.path {
					t.Errorf("unlock path %q, want %q", m.unlockPath, tt.path)
				}
			case scrPicker:
				if tt.path != "" && !m.status.err {
					t.Error("a missing vault shows no notice")
				}
			}
		})
	}
}

// TestScreensRender renders every screen in a large and a small terminal
// and checks that the output fits.
func TestScreensRender(t *testing.T) {
	m := unlocked(t)
	folder := addFolder(m, "Production")
	pid := m.v.data.PutProfile(vault.KeyProfile{Name: "deploy", Key: "key", KeyType: "ssh-ed25519", Fingerprint: "SHA256:abc"})
	for i := range 30 {
		m.v.data.PutHost(vault.Host{
			Name: fmt.Sprintf("host-%02d", i), Hostname: "db.example.com", Port: 22, User: "root",
			Auth: vault.AuthKey, KeyProfileID: pid, FolderID: folder,
		})
	}
	h := m.v.data.Hosts[0]
	hk := &sshclient.HostKeyError{Host: "db.example.com", Key: "ssh-ed25519 AAAA", Fingerprint: "SHA256:new", Trusted: []string{"SHA256:old"}}
	profile, _ := m.v.data.Profile(pid)

	unlockedScreens := []func(){
		func() { m.screen = scrFolders },
		func() { m.showFolderForm(vault.Folder{}) },
		func() { m.showHosts(folder) },
		func() { m.showHosts(folder); press(m, "/", "host") },
		func() { m.showHostForm(h) },
		func() { m.showMove(h) },
		func() { m.screen = scrProfiles },
		func() { m.showProfileForm(profile) },
		func() { m.showPassword() },
		func() { m.confirmDeleteHost(h) },
		func() { m.askHostKey(h.ID, hk) },
		func() { m.askHostKey(h.ID, &sshclient.HostKeyError{Host: "db.example.com", Fingerprint: "SHA256:new"}) },
	}
	lockedScreens := []func(){
		func() { m.showPicker() },
		func() { m.showPicker(); press(m, "o") },
		func() { m.showUnlock(filepath.Join(t.TempDir(), "vault.enc")) },
		func() { m.showCreate("") },
		func() { m.showCreate(filepath.Join(t.TempDir(), "vault.enc")); m.confirmOverwrite() },
	}
	sizes := [][2]int{{100, 32}, {40, 12}, {20, 5}, {10, 3}}
	seen := map[screen]bool{}
	check := func(setups []func()) {
		for _, size := range sizes {
			send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
			for _, setup := range setups {
				setup()
				seen[m.screen] = true
				out := m.View()
				if w, h := lipgloss.Width(out), lipgloss.Height(out); w > size[0] || h > size[1] {
					t.Errorf("screen %d renders %dx%d in a %dx%d terminal", m.screen, w, h, size[0], size[1])
				}
			}
		}
	}
	check(unlockedScreens)
	m.lock("")
	check(lockedScreens)
	if len(seen) != len(screens) {
		t.Errorf("rendered %d of %d screens", len(seen), len(screens))
	}
}

func TestListWindowKeepsCursorVisible(t *testing.T) {
	m := unlocked(t)
	for i := range 50 {
		addHost(m, vault.DefaultFolderID, fmt.Sprintf("host-%02d", i))
	}
	send(m, tea.WindowSizeMsg{Width: 40, Height: 12})
	m.showHosts(vault.DefaultFolderID)
	for i := range 50 {
		out := m.View()
		if !strings.Contains(out, fmt.Sprintf("host-%02d", i)) {
			t.Fatalf("cursor on host %d is not visible:\n%s", i, out)
		}
		if h := lipgloss.Height(out); h > 12 {
			t.Fatalf("view has %d lines", h)
		}
		press(m, "down")
	}
	if m.v.hostCursor != 0 {
		t.Errorf("cursor %d after wrapping around, want 0", m.v.hostCursor)
	}
}

// TestBannerIgnoresBody checks that the title area depends on the terminal
// size only: filtering the hosts must neither swap the banner for the
// one-line title nor move it.
func TestBannerIgnoresBody(t *testing.T) {
	m := unlocked(t)
	for i := range 30 {
		addHost(m, vault.DefaultFolderID, fmt.Sprintf("host-%02d", i))
	}
	m.showHosts(vault.DefaultFolderID)
	head := func() string { return strings.Join(strings.Split(m.View(), "\n")[:3], "\n") }
	for _, size := range [][2]int{{100, 32}, {80, 24}, {50, 14}} {
		send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		m.v.filter.Reset()
		want := head()
		for _, q := range []string{"host-1", "host-17", "nothing matches"} {
			m.v.filter.SetValue(q)
			if head() != want {
				t.Errorf("%dx%d: the title area changes with the filter %q", size[0], size[1], q)
			}
		}
	}
}

// TestSelectionWithoutColor checks that the selected row and option stand
// out when the terminal shows no colors.
func TestSelectionWithoutColor(t *testing.T) {
	if ansi.Strip(row("web", "root@web:22", true, 40)) == ansi.Strip(row("web", "root@web:22", false, 40)) {
		t.Error("a selected row looks like the others")
	}
	labels := []string{"password", "key"}
	if ansi.Strip(segmented(labels, 0)) == ansi.Strip(segmented(labels, 1)) {
		t.Error("the selected option looks like the others")
	}
}

func TestWindow(t *testing.T) {
	tests := []struct{ n, cursor, size, start, end int }{
		{5, 0, 10, 0, 5},
		{50, 0, 3, 0, 3},
		{50, 1, 3, 0, 3},
		{50, 25, 3, 24, 27},
		{50, 49, 3, 47, 50},
	}
	for _, tt := range tests {
		start, end := window(tt.n, tt.cursor, tt.size)
		if start != tt.start || end != tt.end {
			t.Errorf("window(%d, %d, %d) = %d, %d, want %d, %d", tt.n, tt.cursor, tt.size, start, end, tt.start, tt.end)
		}
	}
}

func TestLockDropsLateResults(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	if press(m, "enter") == nil {
		t.Fatal("enter did not connect")
	}
	r := m.busy
	if press(m, "enter") != nil || m.busy != r {
		t.Fatal("a repeated enter started another connect")
	}

	send(m, tickMsg(time.Now().Add(time.Hour)))
	if m.v != nil || m.screen != scrUnlock || !m.idle() {
		t.Fatalf("not locked: screen %d, busy %v", m.screen, m.busy)
	}
	before := *m
	cmds := []tea.Cmd{
		send(m, connectedMsg{req: r, hostID: id, err: &sshclient.HostKeyError{Host: "10.0.0.1", Key: "k"}}),
		send(m, connectedMsg{req: r, hostID: id, err: sshclient.ErrAuthFailed}),
		send(m, savedMsg{epoch: r.epoch, err: vault.ErrModified}),
	}
	for _, cmd := range cmds {
		if cmd != nil {
			t.Error("a stale result returned a command")
		}
	}
	if m.screen != before.screen || m.status != before.status || m.confirm != nil || m.v != nil {
		t.Error("a stale result changed the state")
	}
}

// TestQuitRightAfterLock checks that changes reach the disk when the program
// ends before the store of a locked vault has closed in the background.
func TestQuitRightAfterLock(t *testing.T) {
	m := unlocked(t)
	path := m.v.store.Path()
	addFolder(m, "Staging")
	m.save()      // its write does not run
	press(m, "l") // nor does the flush of the lock
	if err := m.shutdown(); err != nil {
		t.Fatal(err)
	}
	_, d, err := vault.Open(path, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Folders) != 2 {
		t.Errorf("%d folders on disk, want 2", len(d.Folders))
	}
}

// TestUnlockRightAfterLock checks that unlocking again before the store of
// the locked vault has written its last changes loads them, and that the
// late flush of the lock does not break the next save.
func TestUnlockRightAfterLock(t *testing.T) {
	m := unlocked(t)
	addFolder(m, "Staging")
	m.save()              // its write does not run
	lock := press(m, "l") // nor does the flush of the lock, yet
	press(m, testPassword)
	run(m, press(m, "enter"))
	if m.v == nil {
		t.Fatalf("not unlocked: %q", m.status.text)
	}
	if len(m.v.data.Folders) != 2 {
		t.Fatalf("%d folders after unlocking again, want 2", len(m.v.data.Folders))
	}
	run(m, lock)
	addFolder(m, "Prod")
	run(m, m.save())
	if m.status.err {
		t.Fatalf("save after unlocking again failed: %q", m.status.text)
	}
}

// TestLockAfterFailedSave checks the report of changes that are lost when a
// vault changed on disk is locked.
func TestLockAfterFailedSave(t *testing.T) {
	m := unlocked(t)
	f, err := os.OpenFile(m.v.store.Path(), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	addFolder(m, "Staging")
	run(m, m.save())
	if !m.status.err {
		t.Fatal("the save did not fail")
	}
	run(m, press(m, "l"))
	if m.screen != scrUnlock || !m.status.err || len(m.closing) != 0 {
		t.Fatalf("screen %d, status %+v, %d stores closing", m.screen, m.status, len(m.closing))
	}
	if m.status == fail(vault.ErrModified) {
		t.Error("the locked vault shows the advice for an unlocked one")
	}
}

// TestProgressCleared checks that a progress message goes away with the
// result of its request.
func TestProgressCleared(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "enter")
	send(m, connectedMsg{req: m.busy, hostID: id, err: &sshclient.HostKeyError{Host: "10.0.0.1", Key: "k"}})
	if m.screen != scrConfirm || m.status != (status{}) {
		t.Errorf("host key question: screen %d, status %+v", m.screen, m.status)
	}
	press(m, "esc", "enter")
	send(m, connectedMsg{req: m.busy, hostID: id, sess: &sshclient.Session{}})
	send(m, sessionEndedMsg{epoch: m.epoch})
	if m.screen != scrHosts || m.status != (status{}) {
		t.Errorf("after the session: screen %d, status %+v", m.screen, m.status)
	}
}

func TestTitleFollowsState(t *testing.T) {
	m := unlocked(t)
	if m.title != "vaultty" {
		t.Fatalf("unlocked: title %q", m.title)
	}
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "enter")
	send(m, connectedMsg{req: m.busy, hostID: id, sess: &sshclient.Session{}})
	if m.title != "vaultty · web" {
		t.Fatalf("in session: title %q", m.title)
	}
	send(m, sessionEndedMsg{epoch: m.epoch})
	if m.title != "vaultty" {
		t.Fatalf("after the session: title %q", m.title)
	}
	press(m, "esc", "l")
	if m.v != nil || m.title != "vaultty 🔒" {
		t.Fatalf("locked: title %q", m.title)
	}
}

func TestAutoLock(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "enter")
	send(m, connectedMsg{req: m.busy, hostID: id, sess: &sshclient.Session{}})

	send(m, tickMsg(time.Now().Add(time.Hour)))
	if m.v == nil {
		t.Fatal("locked during an SSH session")
	}
	send(m, sessionEndedMsg{epoch: m.epoch})
	send(m, tickMsg(time.Now().Add(time.Second)))
	if m.v == nil {
		t.Fatal("locked right after the session ended")
	}
	send(m, tickMsg(time.Now().Add(m.cfg.AutoLock())))
	if m.v != nil || m.screen != scrUnlock {
		t.Fatal("not locked after the idle time")
	}
}

func TestAutoLockOff(t *testing.T) {
	m := unlocked(t)
	m.cfg.AutoLockMinutes = -1
	send(m, tickMsg(time.Now().Add(24*time.Hour)))
	if m.v == nil {
		t.Fatal("locked although auto-lock is off")
	}
}

func TestErrText(t *testing.T) {
	sentinels := []error{
		vault.ErrWrongPassword, vault.ErrNewerVault, vault.ErrFormat, vault.ErrExists, vault.ErrIsDir, vault.ErrModified,
		vault.ErrWeakPassword, vault.ErrDefaultFolder, vault.ErrProfileInUse, vault.ErrNotFound,
		vault.ErrNoKey, vault.ErrKeyTooLarge,
		sshclient.ErrAuthFailed, sshclient.ErrUnknownAuth, sshclient.ErrNotPrivateKey,
		sshclient.ErrPassphraseRequired, sshclient.ErrWrongPassphrase, sshclient.ErrConnectionLost,
		fs.ErrNotExist, fs.ErrPermission, context.Canceled, os.ErrDeadlineExceeded,
	}
	seen := map[string]error{}
	for _, err := range sentinels {
		text := errText(err)
		if text == errText(errors.New(err.Error())) {
			t.Errorf("%v has no text of its own", err)
		}
		if wrapped := errText(fmt.Errorf("context: %w", err)); wrapped != text {
			t.Errorf("wrapped %v maps to another text", err)
		}
		if other, ok := seen[text]; ok {
			t.Errorf("%v and %v share a text", err, other)
		}
		seen[text] = err
	}

	others := []error{
		&fs.PathError{Op: "open", Path: "/x", Err: fs.ErrNotExist},
		&net.DNSError{Name: "nowhere.example", IsNotFound: true},
		&net.OpError{Op: "dial", Err: timeoutError{}},
	}
	for _, err := range others {
		if errText(err) == errText(errors.New(err.Error())) {
			t.Errorf("%v has no text of its own", err)
		}
	}
}

// TestStatusControlCharacters checks that an error text from a server, here a
// host key type sent before the host key is checked, cannot send escape
// sequences to the terminal.
func TestStatusControlCharacters(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "enter")
	err := errors.New("ssh: handshake failed: ssh: unknown key algorithm: \x1b]52;c;ZWNobyBoaQo=\a\x1b[2J\x9b2J")
	send(m, connectedMsg{req: m.busy, hostID: id, err: err})
	out := m.View()
	for _, seq := range []string{"\x1b]", "\x1b[2J", "\a", "\x9b"} {
		if strings.Contains(out, seq) {
			t.Errorf("the view contains %q", seq)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestGlyphs(t *testing.T) {
	for r, g := range glyphs {
		for _, row := range g {
			if utf8.RuneCountInString(row) != utf8.RuneCountInString(g[0]) {
				t.Errorf("glyph %q has rows of different widths", r)
			}
		}
	}
}
