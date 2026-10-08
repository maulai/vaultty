// Package tui is the terminal user interface of vaultty: choosing, creating
// and unlocking vaults, managing folders, hosts and key profiles, and handing
// the terminal over to SSH sessions.
package tui

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"slices"
	"time"
	"unicode/utf16"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/config"
	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
)

// screen selects the key handler and the view of the model.
type screen int

const (
	scrPicker screen = iota
	scrOpenFile
	scrUnlock
	scrCreate
	scrConfirm
	scrFolders
	scrFolderForm
	scrMove
	scrHosts
	scrHostForm
	scrProfiles
	scrProfileForm
	scrPassword
)

var screens = [...]struct {
	key  func(*model, tea.KeyMsg) tea.Cmd
	view func(*model) string
}{
	scrPicker:      {(*model).pickerKey, (*model).pickerView},
	scrOpenFile:    {(*model).openFileKey, (*model).openFileView},
	scrUnlock:      {(*model).unlockKey, (*model).unlockView},
	scrCreate:      {(*model).createKey, (*model).createView},
	scrConfirm:     {(*model).confirmKey, (*model).confirmView},
	scrFolders:     {(*model).foldersKey, (*model).foldersView},
	scrFolderForm:  {(*model).folderFormKey, (*model).folderFormView},
	scrMove:        {(*model).moveKey, (*model).moveView},
	scrHosts:       {(*model).hostsKey, (*model).hostsView},
	scrHostForm:    {(*model).hostFormKey, (*model).hostFormView},
	scrProfiles:    {(*model).profilesKey, (*model).profilesView},
	scrProfileForm: {(*model).profileFormKey, (*model).profileFormView},
	scrPassword:    {(*model).passwordKey, (*model).passwordView},
}

// model is the Bubble Tea model of the application.
type model struct {
	cfg     *config.Config
	version string

	width, height int
	screen        screen
	status        status
	title         string // window title last sent to the terminal

	epoch  uint64             // incremented by lock; results of older epochs are stale
	lastID uint64             // last request id handed out
	busy   req                // request the UI waits for; zero when idle
	cancel context.CancelFunc // aborts the busy request, if it can be aborted

	lastActivity time.Time
	surrogate    rune // high surrogate of a character split over two key events

	closing []*vault.Store // stores of locked vaults that may still be writing

	picker     picker
	unlockPath string
	unlock     *form // master password for unlockPath
	openFile   *form
	create     *form
	confirm    *confirm // question on the confirm screen; lock drops it

	v *session // unlocked state, nil while locked
}

// session is the unlocked state. lock drops it as a whole.
type session struct {
	store *vault.Store
	data  vault.Data

	folderCursor  int
	folderID      string // folder shown on the hosts screen
	hostCursor    int
	filter        textinput.Model
	filtering     bool // the filter has the focus
	moveHostID    string
	moveCursor    int
	profileCursor int

	folderForm   *form
	hostForm     *form // stays open while a key profile form started from it is shown
	profileForm  *form
	passwordForm *form

	sessionName string // host name while an SSH session runs
}

// status is the message line under the screen content.
type status struct {
	text string
	err  bool
}

func fail(err error) status      { return status{errText(err), true} }
func problem(text string) status { return status{text, true} }
func notice(text string) status  { return status{text: text} }

// req identifies an async request. Its result is stale when the vault was
// locked in between or the UI stopped waiting for it.
type req struct{ epoch, id uint64 }

func (m *model) newReq() req {
	m.lastID++
	return req{m.epoch, m.lastID}
}

// start makes the UI wait for a new request. Keys are ignored until finish
// accepts its result; esc aborts a request that has a cancel function.
func (m *model) start(text string) req {
	m.busy = m.newReq()
	m.status = notice(text)
	return m.busy
}

// finish reports whether r is the request the UI waits for. If so, it ends
// the wait and clears the progress message, so the caller shows the result.
func (m *model) finish(r req) bool {
	if r.id == 0 || r != m.busy {
		return false
	}
	m.stopWaiting()
	m.status = status{}
	return true
}

// stopWaiting ends the wait for the busy request; its result will be dropped.
func (m *model) stopWaiting() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
	m.busy = req{}
}

func (m *model) idle() bool { return m.busy.id == 0 }

// Messages from commands. Results carry the req or epoch they belong to.
type (
	tickMsg time.Time

	// checkedMsg reports whether a vault file exists (err == nil).
	checkedMsg struct {
		req  req
		path string
		err  error
	}

	// openedMsg is the result of unlocking or creating a vault.
	openedMsg struct {
		req     req
		store   *vault.Store
		data    vault.Data
		created bool
		err     error
	}

	// savedMsg reports the result of writing the vault or the config.
	savedMsg struct {
		epoch uint64
		err   error
	}

	// lockedMsg reports that the store of a locked vault wrote its last
	// changes and wiped its key.
	lockedMsg struct {
		epoch uint64
		store *vault.Store
		err   error
	}

	connectedMsg struct {
		req    req
		hostID string
		sess   *sshclient.Session
		err    error
	}

	sessionEndedMsg struct {
		epoch uint64
		err   error
	}

	// keyCheckedMsg carries a validated key profile, ready to be stored.
	keyCheckedMsg struct {
		req       req
		profile   vault.KeyProfile
		unchecked bool // the key file is missing here and was accepted as is
		err       error
	}

	passwordChangedMsg struct {
		req req
		err error
	}
)

// newModel starts with the create screen on the first run and with the
// unlock screen of the configured vault otherwise. A configured vault that
// turns out to be missing leads to the picker, never to the create screen.
func newModel(cfg *config.Config, firstRun bool, version string) model {
	m := model{cfg: cfg, version: version, lastActivity: time.Now()}
	switch {
	case firstRun:
		m.showCreate(cfg.VaultPath)
	case cfg.VaultPath == "":
		m.screen = scrPicker
	default:
		m.showUnlock(cfg.VaultPath)
	}
	m.refreshPicker()
	return m
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tick(), m.checkPaths())
}

// Update applies msg and keeps the terminal title in sync with the state.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	cmd := tea.Batch(m.update(msg), m.syncTitle())
	return m, cmd
}

func (m model) View() string {
	return screens[m.screen].view(&m)
}

func (m *model) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		return m.key(msg)
	case tickMsg:
		return m.tick(time.Time(msg))
	case checkedMsg:
		return m.checked(msg)
	case openedMsg:
		return m.opened(msg)
	case savedMsg:
		if msg.epoch == m.epoch && msg.err != nil {
			m.status = fail(msg.err)
		}
	case lockedMsg:
		m.locked(msg)
	case connectedMsg:
		return m.connected(msg)
	case sessionEndedMsg:
		return m.sessionEnded(msg)
	case keyCheckedMsg:
		return m.keyChecked(msg)
	case passwordChangedMsg:
		m.passwordChanged(msg)
	}
	return nil
}

func (m *model) key(k tea.KeyMsg) tea.Cmd {
	// Windows consoles deliver a character outside the BMP as two key events,
	// one per UTF-16 surrogate. Join them before the key is used.
	high := m.surrogate
	m.surrogate = 0
	if k.Type == tea.KeyRunes && len(k.Runes) == 1 && utf16.IsSurrogate(k.Runes[0]) {
		r := k.Runes[0]
		if r < 0xdc00 {
			m.surrogate = r
			return nil
		}
		if high == 0 {
			return nil // a low surrogate without its high half
		}
		k.Runes = []rune{utf16.DecodeRune(high, r)}
	}
	if k.Type == tea.KeyCtrlC {
		return tea.Quit
	}
	m.lastActivity = time.Now()
	if !m.idle() {
		if k.Type == tea.KeyEsc && m.cancel != nil {
			m.stopWaiting()
			m.status = notice("Cancelled.")
		}
		return nil
	}
	m.status = status{}
	return screens[m.screen].key(m, k)
}

// size returns the terminal size, or a default before the first resize.
func (m *model) size() (w, h int) {
	if m.width <= 0 || m.height <= 0 {
		return 80, 24
	}
	return m.width, m.height
}

// bodyWidth is the width of the content column at the current size.
func (m *model) bodyWidth() int {
	w, _ := m.size()
	return contentWidth(w)
}

const tickInterval = 30 * time.Second

func tick() tea.Cmd {
	return tea.Tick(tickInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// tick locks an unlocked vault after the configured idle time. A running
// SSH session counts as activity.
func (m *model) tick(now time.Time) tea.Cmd {
	limit := m.cfg.AutoLock()
	if m.v == nil || m.v.sessionName != "" || limit <= 0 || now.Sub(m.lastActivity) < limit {
		return tick()
	}
	return tea.Batch(tick(), m.lock("Locked after inactivity."))
}

// lock drops the unlocked state and shows the unlock screen of the same
// vault. The store writes pending changes and wipes its key in the
// background. Until then it stays in closing, so that Run still writes it
// out when the program ends first.
func (m *model) lock(text string) tea.Cmd {
	st := m.v.store
	m.stopWaiting()
	m.v, m.confirm = nil, nil
	m.closing = append(m.closing, st)
	m.epoch++
	m.showUnlock(st.Path())
	m.status = notice(text)
	epoch := m.epoch
	return func() tea.Msg {
		err := st.Flush()
		st.Close()
		return lockedMsg{epoch, st, err}
	}
}

// locked forgets a store that has closed and reports changes it could not
// write.
func (m *model) locked(msg lockedMsg) {
	m.closing = slices.DeleteFunc(m.closing, func(st *vault.Store) bool { return st == msg.store })
	switch {
	case msg.err == nil || msg.epoch != m.epoch:
	case errors.Is(msg.err, vault.ErrModified):
		m.status = problem("Vault locked. Unsaved changes were discarded: another program changed the vault file.")
	default:
		m.status = problem("Vault locked, but the last changes were not saved. " + errText(msg.err))
	}
}

// save takes a snapshot of the data now and writes it in the background.
func (m *model) save() tea.Cmd {
	st, epoch := m.v.store, m.epoch
	if err := st.Snapshot(m.v.data); err != nil {
		m.status = fail(err)
		return nil
	}
	return func() tea.Msg { return savedMsg{epoch, st.Flush()} }
}

// saveConfig records the current vault in the config file in the background.
func (m *model) saveConfig() tea.Cmd {
	cfg, epoch := *m.cfg, m.epoch
	return func() tea.Msg { return savedMsg{epoch, cfg.SaveRemembered(cfg.VaultPath)} }
}

func (m *model) windowTitle() string {
	switch {
	case m.v == nil:
		return "vaultty 🔒"
	case m.v.sessionName != "":
		return "vaultty · " + m.v.sessionName
	}
	return "vaultty"
}

// syncTitle sets the window title when the state calls for another one.
func (m *model) syncTitle() tea.Cmd {
	t := m.windowTitle()
	if t == m.title {
		return nil
	}
	m.title = t
	return tea.SetWindowTitle(t)
}

var errTexts = []struct {
	err  error
	text string
}{
	{vault.ErrWrongPassword, "Wrong password, or the vault file is damaged."},
	{vault.ErrNewerVault, "This vault was written by a newer version of vaultty. Please update."},
	{vault.ErrFormat, "This is not a vault file, or it is damaged."},
	{vault.ErrExists, "A file with this name already exists."},
	{vault.ErrIsDir, "This is a folder. Add a file name, e.g. vault.enc."},
	{vault.ErrModified, "Not saved: another program changed the vault file. Lock and unlock to load it."},
	{vault.ErrWeakPassword, "The password needs at least 12 characters."},
	{vault.ErrDefaultFolder, "The default folder cannot be deleted."},
	{vault.ErrProfileInUse, "The key profile is used by hosts."},
	{vault.ErrNotFound, "The host or folder no longer exists."},
	{vault.ErrNoKey, "The key profile has no key."},
	{vault.ErrKeyTooLarge, "The key file is too large to be a private key."},
	{sshclient.ErrAuthFailed, "Authentication failed. Check the user, password or key."},
	{sshclient.ErrUnknownAuth, "Unknown authentication method."},
	{sshclient.ErrNotPrivateKey, "Not a private key. Choose an OpenSSH or PEM private key, not a .pub file."},
	{sshclient.ErrPassphraseRequired, "The key is encrypted. Enter its passphrase."},
	{sshclient.ErrWrongPassphrase, "Wrong passphrase for the key."},
	{sshclient.ErrConnectionLost, "Connection lost: the server stopped answering."},
	{fs.ErrNotExist, "File not found."},
	{fs.ErrPermission, "Permission denied."},
	{context.Canceled, "Cancelled."},
}

// errText turns an error into a message for the status line.
func errText(err error) string {
	if pe, ok := errors.AsType[*fs.PathError](err); ok {
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return fmt.Sprintf(`File "%s" not found.`, pe.Path)
		case errors.Is(err, fs.ErrPermission):
			return fmt.Sprintf(`No permission to access "%s".`, pe.Path)
		}
	}
	for _, e := range errTexts {
		if errors.Is(err, e.err) {
			return e.text
		}
	}
	if dns, ok := errors.AsType[*net.DNSError](err); ok && dns.IsNotFound {
		return fmt.Sprintf(`Host "%s" not found.`, dns.Name)
	}
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() { // incl. os.ErrDeadlineExceeded
		return "The connection timed out."
	}
	return "Error: " + err.Error()
}
