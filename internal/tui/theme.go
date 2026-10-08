package tui

import (
	"fmt"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Neon palette.
var (
	colorBg       = lipgloss.Color("#0b0e16")
	colorText     = lipgloss.Color("#c6d0f5")
	colorMuted    = lipgloss.Color("#5c6685")
	colorAccent   = lipgloss.Color("#2ae6ff")
	colorViolet   = lipgloss.Color("#a07cff")
	colorGreen    = lipgloss.Color("#3affa3")
	colorRed      = lipgloss.Color("#ff5f6e")
	colorSelected = lipgloss.Color("#1d2435")
)

// gradient is the color ramp of the banners: cyan, violet, pink.
var gradient = [3][3]float64{{0x2a, 0xe6, 0xff}, {0xa0, 0x7c, 0xff}, {0xff, 0x5f, 0xd2}}

var (
	textStyle   = lipgloss.NewStyle().Foreground(colorText)
	mutedStyle  = lipgloss.NewStyle().Foreground(colorMuted)
	accentStyle = lipgloss.NewStyle().Foreground(colorAccent).Bold(true)
	labelStyle  = lipgloss.NewStyle().Foreground(colorViolet).Bold(true)
	errStyle    = lipgloss.NewStyle().Foreground(colorRed)
	okStyle     = lipgloss.NewStyle().Foreground(colorGreen)
	chipStyle   = lipgloss.NewStyle().Foreground(colorMuted).Padding(0, 1)
	chipOnStyle = lipgloss.NewStyle().Foreground(colorBg).Background(colorAccent).Bold(true)
)

const maxContentWidth = 78

// contentWidth is the width of the centered content column.
func contentWidth(termWidth int) int {
	return min(max(termWidth-6, 20), maxContentWidth, termWidth)
}

// inputWidth is the width of a text input in a column of the given width,
// leaving room for the bar and the cursor.
func inputWidth(width int) int { return width - 3 }

// binding is one entry of the help bar.
type binding struct{ key, desc string }

// Help bars while waiting for a request.
var (
	busyHelp   = []binding{{"ctrl+c", "quit"}}
	cancelHelp = []binding{{"esc", "cancel"}, {"ctrl+c", "quit"}}
)

// Smallest terminal the screens are laid out for.
const minWidth, minHeight = 20, 5

// minBodyHeight is the number of lines a body keeps below a pixel banner.
const minBodyHeight = 10

// page lays out a screen: title, body, status line and help bar. body gets
// the content width and the number of lines it may fill. The pixel banner
// replaces the one-line title when the terminal is large enough; the body
// does not decide it, so the title stays put while the body changes.
func (m *model) page(word, subtitle string, help []binding, body func(width, height int) string) string {
	w, h := m.size()
	if w < minWidth || h < minHeight {
		return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, ansi.Truncate("Terminal too small", w, "…"))
	}
	cw := contentWidth(w)
	switch {
	case m.cancel != nil:
		help = cancelHelp
	case !m.idle():
		help = busyHelp
	}
	helpText := helpView(help, w-4)
	if lipgloss.Height(helpText) > h/3 { // leave the room to the content
		helpText = helpView(busyHelp, w-4)
	}
	// Lines left for title, body and status: all but the help bar, the blank
	// line above it and the one under the title.
	room := h - lipgloss.Height(helpText) - 2

	head, gap, bannerH := accentStyle.Render("» "+word+" «"), "\n", 5
	if subtitle != "" {
		bannerH += 2
	}
	if b := banner(word); b.width <= cw && room-bannerH >= minBodyHeight {
		head, gap = b.text, "\n\n"
	}
	head = center(cw, head)
	if subtitle != "" {
		head += gap + center(cw, mutedStyle.Render(ansi.Truncate(subtitle, cw, "…")))
	}

	status := m.status.view(cw)
	statusH := 0
	if status != "" {
		statusH = lipgloss.Height(status) + 1
		status = "\n\n" + status
	}
	content := lipgloss.NewStyle().Width(cw).Render(body(cw, max(room-lipgloss.Height(head)-statusH, 1)))
	return frame(w, h, head+"\n\n"+content+status, helpText)
}

// frame centers content in the terminal and pins the help bar to the bottom,
// below a blank line. Content taller than the room left is cut off.
func frame(w, h int, content, help string) string {
	room := max(h-lipgloss.Height(help)-1, 1)
	if lines := strings.Split(content, "\n"); len(lines) > room {
		content = strings.Join(lines[:room], "\n")
	}
	return lipgloss.Place(w, room, lipgloss.Center, lipgloss.Center, content) + "\n\n" +
		lipgloss.PlaceHorizontal(w, lipgloss.Center, help)
}

func center(width int, s string) string {
	return lipgloss.PlaceHorizontal(width, lipgloss.Center, s)
}

// helpView renders bindings as "key desc  •  key desc", wrapped to width.
func helpView(bindings []binding, width int) string {
	const sep = "  •  "
	sepW := ansi.StringWidth(sep)
	var lines []string
	line, lineW := "", 0
	for _, b := range bindings {
		item := ansi.Truncate(accentStyle.Render(b.key)+" "+mutedStyle.Render(b.desc), width, "…")
		itemW := ansi.StringWidth(item)
		switch {
		case line == "":
			line, lineW = item, itemW
		case lineW+sepW+itemW > width:
			lines = append(lines, line)
			line, lineW = item, itemW
		default:
			line += mutedStyle.Render(sep) + item
			lineW += sepW + itemW
		}
	}
	return strings.Join(append(lines, line), "\n")
}

func (s status) view(width int) string {
	// Error texts can carry strings from a server, such as a host key type.
	// Their control characters must not reach the terminal.
	s.text = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return utf8.RuneError
		}
		return r
	}, s.text)
	switch {
	case s.text == "":
		return ""
	case s.err:
		return errStyle.Width(width).Render("✗ " + s.text)
	}
	return okStyle.Width(width).Render(s.text)
}

// art is a rendered banner.
type art struct {
	text  string
	width int
}

var banners sync.Map // word -> art

// banner renders word in the block font with the neon gradient.
func banner(word string) art {
	if a, ok := banners.Load(word); ok {
		return a.(art)
	}
	var rows [5]string
	for i, r := range word {
		g, ok := glyphs[r]
		if !ok {
			g = glyphs[' ']
		}
		for y := range rows {
			if i > 0 {
				rows[y] += " "
			}
			rows[y] += g[y]
		}
	}
	width := utf8.RuneCountInString(rows[0])
	var b strings.Builder
	for y, line := range rows {
		if y > 0 {
			b.WriteByte('\n')
		}
		x := 0
		for _, r := range line {
			if r == ' ' {
				b.WriteByte(' ')
			} else {
				b.WriteString(lipgloss.NewStyle().Foreground(gradientAt(x, width)).Render(string(r)))
			}
			x++
		}
	}
	a := art{b.String(), width}
	banners.Store(word, a)
	return a
}

// gradientAt returns the gradient color of column x in a banner of width
// columns.
func gradientAt(x, width int) lipgloss.Color {
	t := 2 * float64(x) / float64(max(width-1, 1))
	seg := min(int(t), 1)
	a, b := gradient[seg], gradient[seg+1]
	c := func(i int) int { return int(a[i] + (b[i]-a[i])*(t-float64(seg))) }
	return lipgloss.Color(fmt.Sprintf("#%02x%02x%02x", c(0), c(1), c(2)))
}

// glyphs is a 5-row block font. All rows of a glyph have the same width.
var glyphs = map[rune][5]string{
	'A': {" ██ ", "█  █", "████", "█  █", "█  █"},
	'B': {"███ ", "█  █", "███ ", "█  █", "███ "},
	'C': {" ███", "█   ", "█   ", "█   ", " ███"},
	'D': {"███ ", "█  █", "█  █", "█  █", "███ "},
	'E': {"████", "█   ", "███ ", "█   ", "████"},
	'F': {"████", "█   ", "███ ", "█   ", "█   "},
	'G': {" ███", "█   ", "█ ██", "█  █", " ███"},
	'H': {"█  █", "█  █", "████", "█  █", "█  █"},
	'I': {"███", " █ ", " █ ", " █ ", "███"},
	'J': {"███", "  █", "  █", "█ █", "██ "},
	'K': {"█  █", "█ █ ", "██  ", "█ █ ", "█  █"},
	'L': {"█   ", "█   ", "█   ", "█   ", "████"},
	'M': {"█   █", "██ ██", "█ █ █", "█   █", "█   █"},
	'N': {"█  █", "██ █", "█ ██", "█  █", "█  █"},
	'O': {" ██ ", "█  █", "█  █", "█  █", " ██ "},
	'P': {"███ ", "█  █", "███ ", "█   ", "█   "},
	'Q': {" ██ ", "█  █", "█  █", "█ ██", " ███"},
	'R': {"███ ", "█  █", "███ ", "█ █ ", "█  █"},
	'S': {" ███", "█   ", " ██ ", "   █", "███ "},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'U': {"█  █", "█  █", "█  █", "█  █", " ██ "},
	'V': {"█   █", "█   █", "█   █", " █ █ ", "  █  "},
	'W': {"█   █", "█   █", "█ █ █", "██ ██", "█   █"},
	'X': {"█   █", " █ █ ", "  █  ", " █ █ ", "█   █"},
	'Y': {"█   █", " █ █ ", "  █  ", "  █  ", "  █  "},
	'Z': {"████", "  █ ", " █  ", "█   ", "████"},
	' ': {"  ", "  ", "  ", "  ", "  "},
}

// row renders a list entry. A selected row starts with a bar, so that it
// stands out without colors too. Every segment of a selected row carries the
// background color itself, because a nested style reset would end a
// background set on the whole line.
func row(title, sub string, selected bool, width int) string {
	inner := width - 4 // two cells of padding on each side
	title = ansi.Truncate(title, max(inner-2, 1), "…")
	if room := inner - 2 - ansi.StringWidth(title) - 2; sub != "" && room > 0 {
		sub = "  " + ansi.Truncate(sub, room, "…")
	} else {
		sub = ""
	}
	gap := max(inner-ansi.StringWidth(title)-ansi.StringWidth(sub)-1, 1)

	base, titleStyle, subStyle, mark, lead := lipgloss.NewStyle(), mutedStyle, mutedStyle, mutedStyle, "  "
	if selected {
		base = base.Background(colorSelected)
		titleStyle = base.Foreground(colorAccent).Bold(true)
		subStyle = base.Foreground(colorText)
		mark = base.Foreground(colorAccent)
		lead = "▎ "
	}
	return mark.Render(lead) + titleStyle.Render(title) + subStyle.Render(sub) +
		base.Render(strings.Repeat(" ", gap)) + mark.Render("›") + base.Render("  ")
}

// listView renders n rows into at most height lines. When they do not fit,
// it shows a window around the cursor, between "↑ more" and "↓ more" markers
// when there is room for them.
func listView(n, cursor, height int, render func(i int) string) string {
	height = max(height, 1)
	markers := n > height && height >= 3
	if markers {
		height -= 2
	}
	start, end := window(n, cursor, height)
	var lines []string
	if markers {
		lines = append(lines, marker(start > 0, "↑ more"))
	}
	for i := start; i < end; i++ {
		lines = append(lines, render(i))
	}
	if markers {
		lines = append(lines, marker(end < n, "↓ more"))
	}
	return strings.Join(lines, "\n")
}

// window returns the range [start, end) of n items that fits into size slots
// with the cursor near the middle.
func window(n, cursor, size int) (start, end int) {
	if n <= size {
		return 0, n
	}
	start = min(max(cursor-size/2, 0), n-size)
	return start, start + size
}

// marker is a scroll marker line, empty when there is nothing to scroll to.
func marker(show bool, text string) string {
	if !show {
		return ""
	}
	return mutedStyle.Render("  " + text)
}

// moveCursor handles the list navigation keys and reports whether k was one.
func moveCursor(k tea.KeyMsg, cursor *int, n int) bool {
	d := 0
	switch k.String() {
	case "up", "k":
		d = -1
	case "down", "j":
		d = 1
	default:
		return false
	}
	if n > 0 {
		*cursor = ((*cursor+d)%n + n) % n
	}
	return true
}

// clampCursor keeps a cursor within a list of n items.
func clampCursor(cursor, n int) int { return max(min(cursor, n-1), 0) }

// cursorItem returns the item under the cursor.
func cursorItem[T any](items []T, cursor int) (T, bool) {
	if cursor < 0 || cursor >= len(items) {
		var zero T
		return zero, false
	}
	return items[cursor], true
}

// count formats a number of things: "1 host", "3 hosts".
func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// bar is the neon bar in front of inputs and choices.
func bar(focused bool) string {
	if focused {
		return accentStyle.Render("▎ ")
	}
	return mutedStyle.Render("▎ ")
}

// inputView renders a text input behind the bar. Inputs have no background
// of their own: the text styles inside would reset it.
func inputView(in textinput.Model, width int, focused bool) string {
	in.Width = inputWidth(width)
	in.SetCursor(in.Position()) // recompute the visible part for this width
	return bar(focused) + in.View()
}

// segmented renders options as chips. The selected one is highlighted and
// bracketed, so that it stands out without colors too.
func segmented(labels []string, selected int) string {
	chips := make([]string, len(labels))
	for i, l := range labels {
		if i == selected {
			chips[i] = chipOnStyle.Render("[" + l + "]")
		} else {
			chips[i] = chipStyle.Render(l)
		}
	}
	return strings.Join(chips, " ")
}
