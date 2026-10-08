package tui

import (
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
)

func TestHostKeyPrompt(t *testing.T) {
	tests := []struct {
		name    string
		trusted []string
		key     string
		trusts  bool
	}{
		{"unknown, enter", nil, "enter", true},
		{"unknown, y", nil, "y", true},
		{"unknown, n", nil, "n", false},
		{"changed, enter", []string{"SHA256:old"}, "enter", false},
		{"changed, y", []string{"SHA256:old"}, "y", true},
		{"changed, esc", []string{"SHA256:old"}, "esc", false},
	}
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	offered := vault.KnownHost{Host: "10.0.0.1", Key: "ssh-ed25519 AAAAnew"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.v.data.KnownHosts = nil
			m.showHosts(vault.DefaultFolderID)
			press(m, "enter")
			send(m, connectedMsg{req: m.busy, hostID: id, err: &sshclient.HostKeyError{
				Host: offered.Host, Key: offered.Key, Fingerprint: "SHA256:new", Trusted: tt.trusted,
			}})
			if m.screen != scrConfirm {
				t.Fatalf("no host key question: screen %d", m.screen)
			}
			press(m, tt.key)
			if got := slices.Contains(m.v.data.KnownHosts, offered); got != tt.trusts {
				t.Fatalf("trusted %v, want %v", got, tt.trusts)
			}
			switch {
			case tt.trusts && m.idle():
				t.Error("no reconnect after trusting the key")
			case tt.key == "enter" && !tt.trusts && m.screen != scrConfirm:
				t.Error("enter left the question about a changed key")
			case tt.key != "enter" && !tt.trusts && m.screen != scrHosts:
				t.Error("cancel did not return to the hosts")
			}
			m.stopWaiting()
		})
	}
}

// TestHostKeyPromptFits checks that the question and whole fingerprints stay
// visible on small terminals.
func TestHostKeyPromptFits(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	newFP, oldFP := "SHA256:"+strings.Repeat("n", 43), "SHA256:"+strings.Repeat("o", 43)
	m.askHostKey(id, &sshclient.HostKeyError{Host: "10.0.0.1", Fingerprint: newFP, Trusted: []string{oldFP, oldFP}})
	for _, size := range [][2]int{{50, 14}, {60, 16}, {100, 32}} {
		send(m, tea.WindowSizeMsg{Width: size[0], Height: size[1]})
		out := ansi.Strip(m.View())
		if !strings.Contains(out, m.confirm.question) {
			t.Errorf("%dx%d: the question is not shown", size[0], size[1])
		}
		if size[0] >= 60 && !strings.Contains(out, newFP) {
			t.Errorf("%dx%d: the new fingerprint is split or missing", size[0], size[1])
		}
	}
}

func TestEscCancelsConnect(t *testing.T) {
	m := unlocked(t)
	id := addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "enter")
	r := m.busy
	press(m, "esc")
	if !m.idle() || m.cancel != nil || m.screen != scrHosts {
		t.Fatal("esc did not cancel the connect")
	}
	if send(m, connectedMsg{req: r, hostID: id, err: &sshclient.HostKeyError{Host: "10.0.0.1"}}) != nil || m.screen != scrHosts {
		t.Fatal("the result of a cancelled connect was used")
	}
}

func TestHostsByID(t *testing.T) {
	m := unlocked(t)
	prod := addFolder(m, "Production")
	db := addHost(m, prod, "db")

	// A new host lands in the open folder.
	m.v.folderCursor = slices.IndexFunc(m.v.data.Folders, func(f vault.Folder) bool { return f.ID == prod })
	press(m, "enter", "n", "web", "tab", "web.example.com", "tab", "tab", "deploy")
	run(m, press(m, "enter"))
	i := slices.IndexFunc(m.v.data.Hosts, func(h vault.Host) bool { return h.Name == "web" })
	if i < 0 || m.screen != scrHosts {
		t.Fatalf("host not saved: %q", m.status.text)
	}
	web := m.v.data.Hosts[i]
	if web.FolderID != prod || web.Port != 22 || web.User != "deploy" {
		t.Fatalf("saved %+v", web)
	}

	// Move the selected host to the default folder.
	if h, _ := cursorItem(m.v.visibleHosts(), m.v.hostCursor); h.ID != web.ID {
		t.Fatalf("cursor on %q, want the new host", h.Name)
	}
	press(m, "m")
	m.v.moveCursor = slices.IndexFunc(m.v.data.Folders, func(f vault.Folder) bool { return f.ID == vault.DefaultFolderID })
	run(m, press(m, "enter"))
	if h, _ := m.v.data.Host(web.ID); h.FolderID != vault.DefaultFolderID {
		t.Fatalf("host in folder %q after the move", h.FolderID)
	}
	if hosts := m.v.visibleHosts(); len(hosts) != 1 || m.v.hostCursor != 0 {
		t.Fatalf("%d hosts left with cursor %d", len(hosts), m.v.hostCursor)
	}

	// Delete removes the host under the cursor and nothing else.
	press(m, "d", "y")
	if _, ok := m.v.data.Host(db); ok {
		t.Fatal("host not deleted")
	}
	if _, ok := m.v.data.Host(web.ID); !ok {
		t.Fatal("the wrong host was deleted")
	}
}

// TestEditHostHiddenByFilter checks that the cursor stays on a visible host
// when an edit hides the edited one behind the filter.
func TestEditHostHiddenByFilter(t *testing.T) {
	m := unlocked(t)
	addHost(m, vault.DefaultFolderID, "web1")
	addHost(m, vault.DefaultFolderID, "web2")
	m.showHosts(vault.DefaultFolderID)
	press(m, "/", "web", "enter", "down", "e", "ctrl+u", "db")
	run(m, press(m, "enter"))
	if _, ok := cursorItem(m.v.visibleHosts(), m.v.hostCursor); !ok || m.screen != scrHosts {
		t.Fatalf("cursor %d on %d hosts", m.v.hostCursor, len(m.v.visibleHosts()))
	}
}

func TestMoveToSameFolder(t *testing.T) {
	m := unlocked(t)
	addHost(m, vault.DefaultFolderID, "web")
	m.showHosts(vault.DefaultFolderID)
	press(m, "m")
	if press(m, "enter") != nil || m.screen != scrHosts || m.status != (status{}) {
		t.Fatal("moving a host to its own folder saved the vault")
	}
}

// TestBackKeys checks that the list screens go back with esc, backspace,
// left and h, and that the host list clears an applied filter first.
func TestBackKeys(t *testing.T) {
	m := unlocked(t)
	addHost(m, vault.DefaultFolderID, "web")
	for _, key := range []string{"esc", "backspace", "left", "h"} {
		m.showHosts(vault.DefaultFolderID)
		press(m, "/", "web", "enter", key)
		if m.screen != scrHosts || m.v.filter.Value() != "" {
			t.Fatalf("%s did not clear the filter first", key)
		}
		press(m, key)
		if m.screen != scrFolders {
			t.Fatalf("%s on the hosts: screen %d", key, m.screen)
		}
		press(m, "p", key)
		if m.screen != scrFolders {
			t.Fatalf("%s on the key profiles: screen %d", key, m.screen)
		}
	}
}

func TestFolderDelete(t *testing.T) {
	m := unlocked(t)
	old := addFolder(m, "Old")
	web := addHost(m, old, "web")

	m.v.folderCursor = 0 // the default folder
	press(m, "d")
	if m.screen != scrFolders || !m.status.err {
		t.Fatal("the default folder can be deleted")
	}

	m.v.folderCursor = slices.IndexFunc(m.v.data.Folders, func(f vault.Folder) bool { return f.ID == old })
	run(m, press(m, "d", "y"))
	if _, ok := m.v.data.Folder(old); ok {
		t.Fatal("folder not deleted")
	}
	if h, _ := m.v.data.Host(web); h.FolderID != vault.DefaultFolderID {
		t.Fatalf("host in folder %q, want the default folder", h.FolderID)
	}
	if m.v.folderCursor != 0 {
		t.Errorf("cursor %d, want 0", m.v.folderCursor)
	}
}

func TestHostFormValidation(t *testing.T) {
	m := unlocked(t)
	tests := []struct {
		name string
		keys []string // after opening the form; the name field has the focus
		ok   bool
	}{
		{"valid", []string{"tab", "example.com", "tab", "tab", "root"}, true},
		{"no host", []string{"tab", "tab", "tab", "root"}, false},
		{"port in host", []string{"tab", "example.com:2222", "tab", "tab", "root"}, false},
		{"user in host", []string{"tab", "root@example.com", "tab", "tab", "root"}, false},
		{"bad port", []string{"tab", "example.com", "tab", "ctrl+u", "70000", "tab", "root"}, false},
		{"no user", []string{"tab", "example.com"}, false},
		{"key without profile", []string{"tab", "example.com", "tab", "tab", "root", "tab", "right"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.showHosts(vault.DefaultFolderID)
			press(m, "n")
			press(m, tt.keys...)
			press(m, "enter")
			if saved := m.screen == scrHosts; saved != tt.ok || m.status.err == tt.ok {
				t.Fatalf("saved %v, want %v", saved, tt.ok)
			}
		})
	}
}

func TestParseHostname(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"example.com", "example.com", true},
		{" 10.0.0.1 ", "10.0.0.1", true},
		{"::1", "::1", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"fe80::1%eth0", "fe80::1%eth0", true},
		{"", "", false},
		{"example.com:22", "", false},
		{"10.0.0.1:22", "", false},
		{"[::1]:22", "", false},
		{"root@example.com", "", false},
		{"my host", "", false},
	}
	for _, tt := range tests {
		got, msg := parseHostname(tt.in)
		if (msg == "") != tt.ok || got != tt.want {
			t.Errorf("parseHostname(%q) = %q, %q", tt.in, got, msg)
		}
	}
}
