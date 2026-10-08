package tui

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/vault"
)

// picker lists the recently used vaults.
type picker struct {
	paths  []string
	cursor int
	exists map[string]error // existence check per path, absent while it runs
	req    req
}

var pickerHelp = []binding{{"↑/↓", "select"}, {"enter", "unlock"}, {"o", "open file"}, {"n", "new vault"}, {"q", "quit"}}

// Fields of the create form.
const (
	createPath = iota
	createPassword
	createRepeat
)

// Fields of the change password form.
const (
	passwordCurrent = iota
	passwordNew
	passwordRepeat
)

// showPicker lists the recent vaults and checks in the background which of
// them exist.
func (m *model) showPicker() tea.Cmd {
	m.refreshPicker()
	m.screen = scrPicker
	return m.checkPaths()
}

// refreshPicker reloads the picker entries and forgets earlier checks.
func (m *model) refreshPicker() {
	paths := m.cfg.Recent()
	m.picker = picker{
		paths:  paths,
		cursor: clampCursor(m.picker.cursor, len(paths)),
		exists: map[string]error{},
		req:    m.newReq(),
	}
}

// checkPaths stats the picker entries in the background. Stat may block for
// a long time on an unreachable network drive.
func (m *model) checkPaths() tea.Cmd {
	r := m.picker.req
	cmds := make([]tea.Cmd, len(m.picker.paths))
	for i, path := range m.picker.paths {
		cmds[i] = func() tea.Msg {
			_, err := os.Stat(path)
			return checkedMsg{r, path, err}
		}
	}
	return tea.Batch(cmds...)
}

func (m *model) checked(msg checkedMsg) tea.Cmd {
	if msg.req != m.picker.req {
		return nil
	}
	m.picker.exists[msg.path] = msg.err
	// A missing vault, e.g. on an unmounted drive, sends the user to the
	// picker unless they already started typing the password.
	if errors.Is(msg.err, fs.ErrNotExist) && m.screen == scrUnlock && msg.path == m.unlockPath &&
		m.unlock.value(0) == "" && m.idle() {
		cmd := m.showPicker()
		m.status = problem(fmt.Sprintf(`Vault "%s" not found. Choose another one.`, filepath.Base(msg.path)))
		return cmd
	}
	return nil
}

func (m *model) pickerKey(k tea.KeyMsg) tea.Cmd {
	p := &m.picker
	if moveCursor(k, &p.cursor, len(p.paths)) {
		return nil
	}
	switch k.String() {
	case "enter":
		if path, ok := cursorItem(p.paths, p.cursor); ok {
			m.showUnlock(path)
		}
	case "o":
		m.openFile = newForm("", textField("Path", "Path of an existing vault file", "", false))
		m.screen = scrOpenFile
	case "n":
		dir := ""
		if m.cfg.VaultPath != "" {
			dir = filepath.Dir(m.cfg.VaultPath) + string(filepath.Separator)
		}
		m.showCreate(dir)
	case "q":
		return tea.Quit
	}
	return nil
}

func (m *model) pickerView() string {
	p := &m.picker
	return m.page("VAULTTY", "Choose a vault  ·  version "+m.version, pickerHelp, func(w, h int) string {
		if len(p.paths) == 0 {
			return mutedStyle.Render("No vaults yet. Press n to create one or o to open a vault file.")
		}
		return listView(len(p.paths), p.cursor, h, func(i int) string {
			return row(filepath.Base(p.paths[i]), p.note(p.paths[i]), i == p.cursor, w)
		})
	})
}

// note describes where a picker entry is and whether it exists.
func (p *picker) note(path string) string {
	dir := filepath.Dir(path)
	err, checked := p.exists[path]
	switch {
	case !checked:
		return "checking…"
	case err == nil:
		return dir
	case errors.Is(err, fs.ErrNotExist):
		return "not found  ·  " + dir
	}
	return "unavailable  ·  " + dir
}

func (m *model) openFileKey(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEsc:
		m.openFile = nil
		return m.showPicker()
	case tea.KeyEnter:
		path, ok := m.absPath(m.openFile.value(0))
		if ok {
			m.openFile = nil
			m.showUnlock(path)
		}
		return nil
	}
	m.openFile.update(k, m.bodyWidth())
	return nil
}

func (m *model) openFileView() string {
	return m.page("OPEN", "Open an existing vault", formHelp(m.openFile, "continue"), m.openFile.view)
}

// absPath expands and resolves a path typed by the user. It sets the status
// and reports false when that is not possible.
func (m *model) absPath(input string) (string, bool) {
	p := vault.ExpandPath(input)
	if p == "" {
		m.status = problem("Enter a path.")
		return "", false
	}
	if os.IsPathSeparator(p[len(p)-1]) {
		m.status = problem("Enter a file name, not a folder.")
		return "", false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		m.status = fail(err)
		return "", false
	}
	return abs, true
}

// dropPasswordForms empties and drops the unlock and create forms. Emptying
// matters: the program keeps its initial model, which shares these forms.
func (m *model) dropPasswordForms() {
	for _, f := range []*form{m.unlock, m.create} {
		if f == nil {
			continue
		}
		for i := range f.fields {
			f.fields[i].input.Reset()
		}
	}
	m.unlock, m.create = nil, nil
}

func (m *model) showUnlock(path string) {
	m.dropPasswordForms()
	m.unlockPath = path
	m.unlock = newForm("", textField("Password", "Master password of this vault", "", true))
	m.screen = scrUnlock
}

func (m *model) unlockKey(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEsc:
		m.dropPasswordForms()
		return m.showPicker()
	case tea.KeyEnter:
		password := m.unlock.value(0)
		if password == "" {
			return nil
		}
		path, r := m.unlockPath, m.start("Unlocking…")
		closing := slices.Clone(m.closing)
		return func() tea.Msg {
			// The same vault, locked a moment ago, may still be writing its
			// last changes; the lock reports any error. Other vaults are not
			// waited for, as their drive may hang.
			for _, old := range closing {
				if old.Path() == path {
					_ = old.Flush()
				}
			}
			st, d, err := vault.Open(path, password)
			return openedMsg{req: r, store: st, data: d, err: err}
		}
	}
	m.unlock.update(k, m.bodyWidth())
	return nil
}

func (m *model) unlockView() string {
	sub := filepath.Base(m.unlockPath) + "  ·  " + filepath.Dir(m.unlockPath)
	help := []binding{{"enter", "unlock"}, {"esc", "vaults"}, {"ctrl+c", "quit"}}
	return m.page("UNLOCK", sub, help, m.unlock.view)
}

// opened takes over a vault that was unlocked or created. The password is
// gone with the forms; only the store keeps the derived key.
func (m *model) opened(msg openedMsg) tea.Cmd {
	if !m.finish(msg.req) {
		if msg.store != nil {
			msg.store.Close()
		}
		return nil
	}
	switch {
	case errors.Is(msg.err, vault.ErrExists):
		m.confirmOverwrite()
		return nil
	case msg.err != nil:
		m.status = fail(msg.err)
		if m.screen == scrUnlock {
			m.showUnlock(m.unlockPath)
		}
		return nil
	}
	m.dropPasswordForms()
	m.v = &session{store: msg.store, data: msg.data, filter: newFilter()}
	m.cfg.Remember(msg.store.Path())
	m.lastActivity = time.Now()
	m.screen = scrFolders
	if msg.created {
		m.status = notice("Vault created.")
	}
	return m.saveConfig()
}

func (m *model) showCreate(path string) {
	m.dropPasswordForms()
	m.create = newForm("",
		textField("Path", "Where to store the encrypted vault file", path, false),
		textField("Password", "Master password, at least 12 characters", "", true),
		textField("Repeat", "Type the password again", "", true),
	)
	m.screen = scrCreate
}

func (m *model) createKey(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEsc:
		m.dropPasswordForms()
		return m.showPicker()
	case tea.KeyEnter:
		if m.create.value(createPassword) != m.create.value(createRepeat) {
			m.status = problem("The passwords do not match.")
			return nil
		}
		return m.createVault(false)
	}
	m.create.update(k, m.bodyWidth())
	return nil
}

// createVault creates the vault described by the create form. An existing
// file is only replaced with overwrite.
func (m *model) createVault(overwrite bool) tea.Cmd {
	path, ok := m.absPath(m.create.value(createPath))
	if !ok {
		return nil
	}
	password, r := m.create.value(createPassword), m.start("Creating the vault…")
	return func() tea.Msg {
		st, d, err := vault.Create(path, password, overwrite)
		return openedMsg{req: r, store: st, data: d, created: true, err: err}
	}
}

func (m *model) confirmOverwrite() {
	path, _ := m.absPath(m.create.value(createPath))
	m.ask(confirm{
		word: "OVERWRITE",
		details: func(int) []string {
			return []string{errStyle.Render("This file already exists:"), textStyle.Render(path)}
		},
		question: "Replace it with a new, empty vault? Everything in it will be lost.",
		yes:      "overwrite",
		strict:   true,
		back:     scrCreate,
		onYes:    func(m *model) tea.Cmd { return m.createVault(true) },
	})
}

func (m *model) createView() string {
	return m.page("NEW VAULT", "Create an encrypted vault", formHelp(m.create, "create"), m.create.view)
}

func (m *model) showPassword() {
	m.v.passwordForm = newForm("",
		textField("Current", "Current master password", "", true),
		textField("New", "New master password, at least 12 characters", "", true),
		textField("Repeat", "Type the new password again", "", true),
	)
	m.screen = scrPassword
}

func (m *model) passwordKey(k tea.KeyMsg) tea.Cmd {
	f := m.v.passwordForm
	switch k.Type {
	case tea.KeyEsc:
		m.v.passwordForm = nil
		m.screen = scrFolders
		return nil
	case tea.KeyEnter:
		if f.value(passwordNew) != f.value(passwordRepeat) {
			m.status = problem("The new passwords do not match.")
			return nil
		}
		st, current, next := m.v.store, f.value(passwordCurrent), f.value(passwordNew)
		r := m.start("Changing the password…")
		return func() tea.Msg { return passwordChangedMsg{r, st.ChangePassword(current, next)} }
	}
	f.update(k, m.bodyWidth())
	return nil
}

func (m *model) passwordChanged(msg passwordChangedMsg) {
	if !m.finish(msg.req) {
		return
	}
	switch {
	case errors.Is(msg.err, vault.ErrWrongPassword):
		m.status = problem("The current password is wrong.")
	case msg.err != nil:
		m.status = fail(msg.err)
	default:
		m.v.passwordForm = nil
		m.screen = scrFolders
		m.status = notice("Master password changed.")
	}
}

func (m *model) passwordView() string {
	f := m.v.passwordForm
	return m.page("PASSWORD", "Change the master password", formHelp(f, "change"), f.view)
}
