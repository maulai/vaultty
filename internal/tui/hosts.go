package tui

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/maulai/vaultty/internal/sshclient"
	"github.com/maulai/vaultty/internal/vault"
)

var filterHelp = []binding{{"↑/↓", "select"}, {"enter", "done"}, {"esc", "clear"}}

// hostsHelp is the help bar of the host list; esc does what escDesc says.
func hostsHelp(escDesc string) []binding {
	return []binding{
		{"↑/↓", "select"}, {"enter", "connect"}, {"n", "new"}, {"e", "edit"}, {"d", "delete"},
		{"m", "move"}, {"/", "filter"}, {"esc", escDesc}, {"l", "lock"}, {"q", "quit"},
	}
}

// Fields of the host form.
const (
	hostName = iota
	hostAddress
	hostPort
	hostUser
	hostAuth
	hostProfile
	hostPassword
)

var authOptions = []option{{vault.AuthPassword, "password"}, {vault.AuthKey, "key"}}

const filterLabel = "Filter "

func newFilter() textinput.Model {
	in := newInput("", false)
	in.Placeholder = "name, host or user"
	return in
}

// hostTitle is the name of a host as shown in lists and titles.
func hostTitle(h vault.Host) string { return cmp.Or(h.Name, h.Hostname) }

func (m *model) showHosts(folderID string) {
	v := m.v
	v.folderID = folderID
	v.hostCursor = 0
	v.filter = newFilter()
	v.filtering = false
	m.screen = scrHosts
}

// visibleHosts returns the hosts of the open folder that match the filter.
func (v *session) visibleHosts() []vault.Host {
	q := strings.ToLower(strings.TrimSpace(v.filter.Value()))
	var hosts []vault.Host
	for _, h := range v.data.Hosts {
		if h.FolderID == v.folderID && strings.Contains(strings.ToLower(h.Name+" "+h.Hostname+" "+h.User), q) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

func (m *model) hostsKey(k tea.KeyMsg) tea.Cmd {
	v := m.v
	if v.filtering {
		m.filterKey(k)
		return nil
	}
	hosts := v.visibleHosts()
	if moveCursor(k, &v.hostCursor, len(hosts)) {
		return nil
	}
	h, ok := cursorItem(hosts, v.hostCursor)
	switch k.String() {
	case "enter":
		if ok {
			return m.connect(h.ID)
		}
	case "n":
		m.showHostForm(vault.Host{Port: 22, Auth: vault.AuthPassword})
	case "e":
		if ok {
			m.showHostForm(h)
		}
	case "d":
		if ok {
			m.confirmDeleteHost(h)
		}
	case "m":
		if ok {
			m.showMove(h)
		}
	case "/":
		v.filtering = true
		v.filter.Focus()
	case "esc", "backspace", "left", "h":
		if v.filter.Value() != "" {
			v.filter.Reset()
			v.hostCursor = 0
		} else {
			m.screen = scrFolders
		}
	case "l":
		return m.lock("Vault locked.")
	case "q":
		return tea.Quit
	}
	return nil
}

// filterKey edits the filter. The arrow keys still move the cursor.
func (m *model) filterKey(k tea.KeyMsg) {
	v := m.v
	switch k.String() {
	case "up", "down":
		moveCursor(k, &v.hostCursor, len(v.visibleHosts()))
		return
	case "esc":
		v.filter.Reset()
		fallthrough
	case "enter":
		v.filtering = false
		v.filter.Blur()
	default:
		updateInput(&v.filter, k, m.bodyWidth()-len(filterLabel))
	}
	v.hostCursor = clampCursor(v.hostCursor, len(v.visibleHosts()))
}

func (m *model) hostsView() string {
	v := m.v
	folder, _ := v.data.Folder(v.folderID)
	total := v.data.FolderSize(v.folderID)
	help := hostsHelp("back")
	switch {
	case v.filtering:
		help = filterHelp
	case v.filter.Value() != "":
		help = hostsHelp("clear filter")
	}
	return m.page("HOSTS", folder.Name+"  ·  "+count(total, "host"), help, func(w, h int) string {
		filtered := v.filtering || v.filter.Value() != ""
		var top string
		if filtered {
			top = labelStyle.Render(filterLabel) + inputView(v.filter, w-len(filterLabel), v.filtering) + "\n\n"
			h -= 2
		}
		hosts := v.visibleHosts()
		var list string
		switch {
		case total == 0:
			list = mutedStyle.Render("No hosts in this folder yet. Press n to add one.")
		case len(hosts) == 0:
			list = mutedStyle.Render("No host matches the filter.")
		default:
			list = listView(len(hosts), v.hostCursor, h, func(i int) string {
				return row(hostTitle(hosts[i]), m.hostSummary(hosts[i]), i == v.hostCursor, w)
			})
		}
		if !filtered {
			return list
		}
		// As tall as the whole list, so that the layout stays put while typing.
		return lipgloss.PlaceVertical(min(total, h)+2, lipgloss.Top, top+list)
	})
}

// hostSummary is the second part of a host row: user@host:port [auth].
func (m *model) hostSummary(h vault.Host) string {
	auth := "password"
	if h.Auth == vault.AuthKey {
		p, _ := m.v.data.Profile(h.KeyProfileID)
		auth = "key: " + cmp.Or(p.Name, "none")
	}
	return fmt.Sprintf("%s@%s  [%s]", h.User, net.JoinHostPort(h.Hostname, strconv.Itoa(h.Port)), auth)
}

func (m *model) confirmDeleteHost(h vault.Host) {
	m.ask(confirm{
		word:     "DELETE",
		question: fmt.Sprintf(`Delete the host "%s"?`, hostTitle(h)),
		yes:      "delete",
		back:     scrHosts,
		onYes: func(m *model) tea.Cmd {
			v := m.v
			v.data.DeleteHost(h.ID)
			v.hostCursor = clampCursor(v.hostCursor, len(v.visibleHosts()))
			m.status = notice("Host deleted.")
			return m.save()
		},
	})
}

// connect dials a host in the background. The key file is read there too, so
// a slow or missing drive does not block the UI. Esc cancels the attempt.
func (m *model) connect(id string) tea.Cmd {
	h, ok := m.v.data.Host(id)
	if !ok {
		return nil
	}
	var p vault.KeyProfile
	if h.Auth == vault.AuthKey {
		if p, ok = m.v.data.Profile(h.KeyProfileID); !ok {
			m.status = problem("This host has no key profile. Press e to choose one.")
			return nil
		}
	}
	known := slices.Clone(m.v.data.KnownHosts)
	ctx, cancel := context.WithCancel(context.Background())
	r := m.start(fmt.Sprintf(`Connecting to "%s"…`, hostTitle(h)))
	m.cancel = cancel
	return func() tea.Msg {
		var key []byte
		if h.Auth == vault.AuthKey {
			var err error
			if key, err = p.ReadKey(); err != nil {
				return connectedMsg{req: r, hostID: id, err: err}
			}
		}
		sess, err := sshclient.Dial(ctx, h, key, p.Passphrase, known)
		return connectedMsg{r, id, sess, err}
	}
}

// connected hands the terminal to a new SSH session, or asks about an
// untrusted host key. A session that is no longer wanted is closed.
func (m *model) connected(msg connectedMsg) tea.Cmd {
	if !m.finish(msg.req) {
		if msg.sess != nil {
			msg.sess.Close()
		}
		return nil
	}
	if hk, ok := errors.AsType[*sshclient.HostKeyError](msg.err); ok {
		m.askHostKey(msg.hostID, hk)
		return nil
	}
	if msg.err != nil {
		m.status = fail(msg.err)
		return nil
	}
	h, _ := m.v.data.Host(msg.hostID)
	m.v.sessionName = hostTitle(h)
	epoch := m.epoch
	return tea.Sequence(
		m.syncTitle(),
		tea.ExitAltScreen,
		// Closing here too covers a session that never ran because the
		// terminal could not be released.
		tea.Exec(msg.sess, func(err error) tea.Msg {
			msg.sess.Close()
			return sessionEndedMsg{epoch, err}
		}),
	)
}

func (m *model) sessionEnded(msg sessionEndedMsg) tea.Cmd {
	if msg.epoch == m.epoch && m.v != nil {
		m.v.sessionName = ""
		m.lastActivity = time.Now()
		if msg.err != nil {
			m.status = fail(msg.err)
		}
	}
	return tea.Sequence(tea.EnterAltScreen, tea.ClearScreen)
}

// askHostKey asks whether to trust a host key. A changed key can mean an
// attack, so only y replaces it; enter does not.
func (m *model) askHostKey(hostID string, hk *sshclient.HostKeyError) {
	c := confirm{
		word:     "HOST KEY",
		subtitle: "Unknown host key",
		details: func(w int) []string {
			return pairs(w,
				[2]string{"Host", textStyle.Render(hk.Host)},
				[2]string{"Fingerprint", okStyle.Render(hk.Fingerprint)},
			)
		},
		question: "Trust this key and connect?",
		yes:      "trust and connect",
		back:     scrHosts,
		onYes: func(m *model) tea.Cmd {
			m.v.data.Trust(hk.Host, hk.Key)
			return tea.Batch(m.save(), m.connect(hostID))
		},
	}
	if hk.Changed() {
		c.subtitle = "The host key has changed"
		// The explanation comes last: it is the first to go on a short terminal.
		c.details = func(w int) []string {
			keys := [][2]string{{"New key", errStyle.Render(hk.Fingerprint)}}
			for i, fp := range hk.Trusted {
				label := ""
				if i == 0 {
					label = "Trusted"
				}
				keys = append(keys, [2]string{label, textStyle.Render(fp)})
			}
			return slices.Concat(
				[]string{errStyle.Bold(true).Render("Warning: " + hk.Host + " presents a different host key."), ""},
				pairs(w, keys...),
				[]string{"", mutedStyle.Render("Someone may be intercepting the connection, or the server was reinstalled.")},
			)
		}
		c.question = "Replace the trusted key and connect?"
		c.yes = "replace and connect"
		c.strict = true
	}
	m.ask(c)
}

func (m *model) showHostForm(h vault.Host) {
	port := ""
	if h.Port != 0 {
		port = strconv.Itoa(h.Port)
	}
	f := newForm(h.ID,
		textField("Name", "Display name, e.g. prod-db", h.Name, false),
		textField("Host", "Host name or IP address", h.Hostname, false),
		textField("Port", "SSH port, usually 22", port, false),
		textField("User", "Login user", h.User, false),
		choiceField("Auth", "Password or key profile", authOptions, h.Auth),
		choiceField("Key profile", "n adds a new profile", m.profileOptions(), h.KeyProfileID),
		textField("Password", "Login password, or sudo password for ctrl+]", h.Password, true),
	)
	f.fields[hostProfile].hidden = h.Auth != vault.AuthKey
	m.v.hostForm = f
	m.screen = scrHostForm
}

func (m *model) profileOptions() []option {
	opts := make([]option, len(m.v.data.KeyProfiles))
	for i, p := range m.v.data.KeyProfiles {
		opts[i] = option{p.ID, p.Name}
	}
	return opts
}

func (m *model) hostFormKey(k tea.KeyMsg) tea.Cmd {
	f := m.v.hostForm
	switch {
	case k.Type == tea.KeyEsc:
		m.v.hostForm = nil
		m.screen = scrHosts
		return nil
	case k.Type == tea.KeyEnter:
		return m.saveHost()
	case k.String() == "n" && f.focus == hostProfile:
		m.showProfileForm(vault.KeyProfile{})
		return nil
	}
	f.update(k, m.bodyWidth())
	f.fields[hostProfile].hidden = f.value(hostAuth) != vault.AuthKey
	return nil
}

func (m *model) saveHost() tea.Cmd {
	v := m.v
	h, msg := hostFromForm(v.hostForm)
	if msg != "" {
		m.status = problem(msg)
		return nil
	}
	h.FolderID = v.folderID
	if old, ok := v.data.Host(h.ID); ok {
		h.FolderID = old.FolderID
	}
	id := v.data.PutHost(h)
	visible := v.visibleHosts()
	if i := slices.IndexFunc(visible, func(h vault.Host) bool { return h.ID == id }); i >= 0 {
		v.hostCursor = i
	} else { // the filter hides the host now
		v.hostCursor = clampCursor(v.hostCursor, len(visible))
	}
	v.hostForm = nil
	m.screen = scrHosts
	m.status = notice("Host saved.")
	return m.save()
}

// hostFromForm validates the host form. It returns a message for the user
// when the input is not valid.
func hostFromForm(f *form) (vault.Host, string) {
	h := vault.Host{
		ID:       f.id,
		Name:     strings.TrimSpace(f.value(hostName)),
		User:     strings.TrimSpace(f.value(hostUser)),
		Auth:     f.value(hostAuth),
		Password: f.value(hostPassword),
	}
	var msg string
	if h.Hostname, msg = parseHostname(f.value(hostAddress)); msg != "" {
		return h, msg
	}
	port, err := strconv.Atoi(strings.TrimSpace(f.value(hostPort)))
	if err != nil || port < 1 || port > 65535 {
		return h, "The port must be a number from 1 to 65535."
	}
	h.Port = port
	if h.User == "" {
		return h, "Enter a user."
	}
	if h.Auth == vault.AuthKey {
		if h.KeyProfileID = f.value(hostProfile); h.KeyProfileID == "" {
			return h, "Choose a key profile, or press n on that field to add one."
		}
	}
	h.Name = cmp.Or(h.Name, h.Hostname)
	return h, ""
}

// parseHostname checks a host name or IP address. Brackets around an IPv6
// address are removed; a port belongs into the port field.
func parseHostname(s string) (string, string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	switch {
	case s == "":
		return "", "Enter a host name or IP address."
	case strings.ContainsAny(s, " \t@"):
		return "", "The host must not contain spaces or @. Enter the user in the user field."
	case strings.Contains(s, ":"):
		if a, err := netip.ParseAddr(s); err != nil || !a.Is6() {
			return "", "Enter the port in the port field."
		}
	}
	return s, ""
}

func (m *model) hostFormView() string {
	f := m.v.hostForm
	word := "EDIT HOST"
	if f.id == "" {
		word = "ADD HOST"
	}
	return m.page(word, "", formHelp(f, "save"), f.view)
}
