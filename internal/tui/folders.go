package tui

import (
	"fmt"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/vault"
)

var (
	foldersHelp = []binding{
		{"↑/↓", "select"}, {"enter", "open"}, {"n", "new"}, {"r", "rename"}, {"d", "delete"},
		{"p", "key profiles"}, {"c", "change password"}, {"l", "lock"}, {"q", "quit"},
	}
	moveHelp = []binding{{"↑/↓", "select"}, {"enter", "move"}, {"esc", "cancel"}}
)

func (m *model) foldersKey(k tea.KeyMsg) tea.Cmd {
	v := m.v
	if moveCursor(k, &v.folderCursor, len(v.data.Folders)) {
		return nil
	}
	f, ok := cursorItem(v.data.Folders, v.folderCursor)
	switch k.String() {
	case "enter":
		if ok {
			m.showHosts(f.ID)
		}
	case "n":
		m.showFolderForm(vault.Folder{})
	case "r":
		if ok {
			m.showFolderForm(f)
		}
	case "d":
		if ok {
			m.confirmDeleteFolder(f)
		}
	case "p":
		v.profileCursor = clampCursor(v.profileCursor, len(v.data.KeyProfiles))
		m.screen = scrProfiles
	case "c":
		m.showPassword()
	case "l":
		return m.lock("Vault locked.")
	case "q":
		return tea.Quit
	}
	return nil
}

func (m *model) foldersView() string {
	v := m.v
	sub := count(len(v.data.Folders), "folder") + "  ·  " + count(len(v.data.Hosts), "host")
	return m.page("FOLDERS", sub, foldersHelp, func(w, h int) string {
		return listView(len(v.data.Folders), v.folderCursor, h, func(i int) string {
			f := v.data.Folders[i]
			return row(f.Name, count(v.data.FolderSize(f.ID), "host"), i == v.folderCursor, w)
		})
	})
}

func (m *model) showFolderForm(f vault.Folder) {
	m.v.folderForm = newForm(f.ID, textField("Name", "Folder name", f.Name, false))
	m.screen = scrFolderForm
}

func (m *model) folderFormKey(k tea.KeyMsg) tea.Cmd {
	v, f := m.v, m.v.folderForm
	switch k.Type {
	case tea.KeyEsc:
		v.folderForm = nil
		m.screen = scrFolders
		return nil
	case tea.KeyEnter:
		name := strings.TrimSpace(f.value(0))
		if name == "" {
			m.status = problem("Enter a folder name.")
			return nil
		}
		id := v.data.PutFolder(vault.Folder{ID: f.id, Name: name})
		v.folderCursor = slices.IndexFunc(v.data.Folders, func(f vault.Folder) bool { return f.ID == id })
		v.folderForm = nil
		m.screen = scrFolders
		m.status = notice("Folder saved.")
		return m.save()
	}
	f.update(k, m.bodyWidth())
	return nil
}

func (m *model) folderFormView() string {
	f := m.v.folderForm
	word := "RENAME"
	if f.id == "" {
		word = "NEW FOLDER"
	}
	return m.page(word, "", formHelp(f, "save"), f.view)
}

func (m *model) confirmDeleteFolder(f vault.Folder) {
	if f.ID == vault.DefaultFolderID {
		m.status = fail(vault.ErrDefaultFolder)
		return
	}
	c := confirm{
		word:     "DELETE",
		question: fmt.Sprintf(`Delete the folder "%s"?`, f.Name),
		yes:      "delete",
		back:     scrFolders,
		onYes: func(m *model) tea.Cmd {
			v := m.v
			if err := v.data.DeleteFolder(f.ID); err != nil {
				m.status = fail(err)
				return nil
			}
			v.folderCursor = clampCursor(v.folderCursor, len(v.data.Folders))
			m.status = notice("Folder deleted.")
			return m.save()
		},
	}
	if n := m.v.data.FolderSize(f.ID); n > 0 {
		def, _ := m.v.data.Folder(vault.DefaultFolderID)
		note := mutedStyle.Render(fmt.Sprintf(`The %s in "%s" will move to "%s".`, count(n, "host"), f.Name, def.Name))
		c.details = func(int) []string { return []string{note} }
	}
	m.ask(c)
}

func (m *model) showMove(h vault.Host) {
	v := m.v
	v.moveHostID = h.ID
	v.moveCursor = max(slices.IndexFunc(v.data.Folders, func(f vault.Folder) bool { return f.ID == h.FolderID }), 0)
	m.screen = scrMove
}

func (m *model) moveKey(k tea.KeyMsg) tea.Cmd {
	v := m.v
	if moveCursor(k, &v.moveCursor, len(v.data.Folders)) {
		return nil
	}
	switch k.String() {
	case "esc":
		m.screen = scrHosts
	case "enter":
		f, ok := cursorItem(v.data.Folders, v.moveCursor)
		if !ok {
			return nil
		}
		m.screen = scrHosts
		if h, _ := v.data.Host(v.moveHostID); h.FolderID == f.ID {
			return nil
		}
		if err := v.data.MoveHost(v.moveHostID, f.ID); err != nil {
			m.status = fail(err)
			return nil
		}
		v.hostCursor = clampCursor(v.hostCursor, len(v.visibleHosts()))
		m.status = notice(fmt.Sprintf(`Moved to "%s".`, f.Name))
		return m.save()
	}
	return nil
}

func (m *model) moveView() string {
	v := m.v
	h, _ := v.data.Host(v.moveHostID)
	return m.page("MOVE", fmt.Sprintf(`Choose a folder for "%s"`, hostTitle(h)), moveHelp, func(w, height int) string {
		return listView(len(v.data.Folders), v.moveCursor, height, func(i int) string {
			f := v.data.Folders[i]
			sub := count(v.data.FolderSize(f.ID), "host")
			if f.ID == h.FolderID {
				sub += "  ·  current"
			}
			return row(f.Name, sub, i == v.moveCursor, w)
		})
	})
}
