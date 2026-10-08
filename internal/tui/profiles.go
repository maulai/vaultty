package tui

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
)

var profilesHelp = []binding{
	{"↑/↓", "select"}, {"enter/e", "edit"}, {"n", "new"}, {"d", "delete"}, {"esc", "back"}, {"l", "lock"}, {"q", "quit"},
}

// Fields of the key profile form.
const (
	profileName = iota
	profileSource
	profileFile
	profilePassphrase
)

var sourceOptions = []option{{vault.KeySourceVault, "in vault"}, {vault.KeySourceFile, "file"}}

func (m *model) profilesKey(k tea.KeyMsg) tea.Cmd {
	v := m.v
	if moveCursor(k, &v.profileCursor, len(v.data.KeyProfiles)) {
		return nil
	}
	p, ok := cursorItem(v.data.KeyProfiles, v.profileCursor)
	switch k.String() {
	case "enter", "e":
		if ok {
			m.showProfileForm(p)
		}
	case "n":
		m.showProfileForm(vault.KeyProfile{})
	case "d":
		if ok {
			m.confirmDeleteProfile(p)
		}
	case "esc", "backspace", "left", "h":
		m.screen = scrFolders
	case "l":
		return m.lock("Vault locked.")
	case "q":
		return tea.Quit
	}
	return nil
}

func (m *model) profilesView() string {
	v := m.v
	return m.page("KEYS", "Key profiles", profilesHelp, func(w, h int) string {
		if len(v.data.KeyProfiles) == 0 {
			return mutedStyle.Render("No key profiles yet. Press n to add one.")
		}
		return listView(len(v.data.KeyProfiles), v.profileCursor, h, func(i int) string {
			p := v.data.KeyProfiles[i]
			return row(p.Name, profileSummary(p, v.data.ProfileUsage(p.ID)), i == v.profileCursor, w)
		})
	})
}

// profileSummary tells where the key is, its type and how many hosts use it.
func profileSummary(p vault.KeyProfile, uses int) string {
	parts := []string{"in vault"}
	if p.IsFile() {
		parts[0] = "file " + p.Path
	}
	if p.KeyType != "" {
		parts = append(parts, p.KeyType)
	}
	return strings.Join(append(parts, count(uses, "host")), "  ·  ")
}

func (m *model) confirmDeleteProfile(p vault.KeyProfile) {
	if n := m.v.data.ProfileUsage(p.ID); n > 0 {
		m.status = problem("The key profile is still used by " + count(n, "host") + ".")
		return
	}
	m.ask(confirm{
		word:     "DELETE",
		question: fmt.Sprintf(`Delete the key profile "%s"?`, p.Name),
		yes:      "delete",
		back:     scrProfiles,
		onYes: func(m *model) tea.Cmd {
			v := m.v
			if err := v.data.DeleteProfile(p.ID); err != nil {
				m.status = fail(err)
				return nil
			}
			v.profileCursor = clampCursor(v.profileCursor, len(v.data.KeyProfiles))
			m.status = notice("Key profile deleted.")
			return m.save()
		},
	})
}

// showProfileForm opens the key profile form. Opened from the host form, it
// returns there and selects the new profile.
func (m *model) showProfileForm(p vault.KeyProfile) {
	m.v.profileForm = newForm(p.ID,
		textField("Name", "Optional; defaults to the key file name", p.Name, false),
		choiceField("Source", "Store the key in the vault, or only its file path",
			sourceOptions, cmp.Or(p.Source, vault.KeySourceVault)),
		textField("Key file", "", p.Path, false),
		textField("Passphrase", "Empty when the key has none", p.Passphrase, true),
	)
	m.describeKeyFile()
	m.screen = scrProfileForm
}

// describeKeyFile explains the key file field for the chosen source.
func (m *model) describeKeyFile() {
	f := m.v.profileForm
	old, _ := m.v.data.Profile(f.id)
	desc := "Private key file to import into the vault"
	switch {
	case f.value(profileSource) == vault.KeySourceFile:
		desc = "Private key file on this computer; only its path is stored"
	case !old.IsFile() && old.Key != "":
		desc = "Empty keeps the stored key; a file replaces it"
	}
	f.fields[profileFile].desc = desc
}

func (m *model) closeProfileForm() {
	m.v.profileForm = nil
	m.screen = scrProfiles
	if m.v.hostForm != nil {
		m.screen = scrHostForm
	}
}

func (m *model) profileFormKey(k tea.KeyMsg) tea.Cmd {
	switch k.Type {
	case tea.KeyEsc:
		m.closeProfileForm()
		return nil
	case tea.KeyEnter:
		return m.checkProfile()
	}
	m.v.profileForm.update(k, m.bodyWidth())
	m.describeKeyFile()
	return nil
}

// checkProfile builds the profile from the form and validates its key in the
// background.
func (m *model) checkProfile() tea.Cmd {
	f := m.v.profileForm
	old, editing := m.v.data.Profile(f.id)
	p := vault.KeyProfile{
		ID:         f.id,
		Name:       strings.TrimSpace(f.value(profileName)),
		Source:     f.value(profileSource),
		Passphrase: f.value(profilePassphrase),
	}
	file := strings.TrimSpace(f.value(profileFile))
	// An unchanged path of a file profile may name a file that only exists
	// on another computer; it is accepted without a check then.
	keep := false
	switch {
	case p.IsFile() && file == "":
		m.status = problem("Enter the path of the key file.")
		return nil
	case p.IsFile():
		keep = editing && old.IsFile() && file == old.Path
		if keep {
			p.Path, p.KeyType, p.Fingerprint = old.Path, old.KeyType, old.Fingerprint
		} else {
			p.Path = vault.PortablePath(file)
		}
		file = p.Path
	case file == "" && editing && !old.IsFile() && old.Key != "":
		p.Key = old.Key
	case file == "":
		m.status = problem("Enter the key file to import.")
		return nil
	}
	if p.Name == "" && file != "" {
		p.Name = filepath.Base(vault.ResolvePath(file))
	}
	if p.Name == "" {
		m.status = problem("Enter a name.")
		return nil
	}
	r := m.start("Checking the key…")
	return func() tea.Msg { return checkKey(r, p, file, keep) }
}

// checkKey reads the key from file, if set, and checks that it opens with
// the passphrase. With keep, a missing file is accepted unchecked.
func checkKey(r req, p vault.KeyProfile, file string, keep bool) keyCheckedMsg {
	key := []byte(p.Key)
	if file != "" {
		b, err := vault.KeyProfile{Source: vault.KeySourceFile, Path: file}.ReadKey()
		if keep && errors.Is(err, fs.ErrNotExist) {
			return keyCheckedMsg{req: r, profile: p, unchecked: true}
		}
		if err != nil {
			return keyCheckedMsg{req: r, err: err}
		}
		key = b
	}
	info, err := sshclient.Inspect(key, p.Passphrase)
	if err != nil {
		return keyCheckedMsg{req: r, err: err}
	}
	p.KeyType, p.Fingerprint = info.Type, info.Fingerprint
	if !p.IsFile() {
		p.Key = string(key)
	}
	return keyCheckedMsg{req: r, profile: p}
}

func (m *model) keyChecked(msg keyCheckedMsg) tea.Cmd {
	if !m.finish(msg.req) {
		return nil
	}
	if msg.err != nil {
		m.status = fail(msg.err)
		return nil
	}
	v := m.v
	id := v.data.PutProfile(msg.profile)
	m.status = notice("Key profile saved.")
	if msg.unchecked {
		m.status = notice("Key profile saved. Its file is not on this computer, so the key was not checked.")
	}
	m.closeProfileForm()
	if f := v.hostForm; f != nil {
		fl := &f.fields[hostProfile]
		fl.options = m.profileOptions()
		fl.choose(id)
	} else {
		v.profileCursor = slices.IndexFunc(v.data.KeyProfiles, func(p vault.KeyProfile) bool { return p.ID == id })
	}
	return m.save()
}

func (m *model) profileFormView() string {
	f := m.v.profileForm
	word, sub := "NEW KEY", ""
	if old, ok := m.v.data.Profile(f.id); ok {
		word, sub = "EDIT KEY", strings.TrimSpace(old.KeyType+"  "+old.Fingerprint)
	}
	return m.page(word, sub, formHelp(f, "save"), f.view)
}
