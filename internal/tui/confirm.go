package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// confirm is a yes/no question on the confirm screen.
type confirm struct {
	word, subtitle string
	details        func(width int) []string // styled lines above the question, or nil
	question       string
	yes            string // help text of the confirming key
	strict         bool   // only y confirms, enter is ignored
	back           screen // shown after the answer
	onYes          func(*model) tea.Cmd
}

func (m *model) ask(c confirm) {
	m.confirm = &c
	m.screen = scrConfirm
}

func (m *model) confirmKey(k tea.KeyMsg) tea.Cmd {
	c := m.confirm
	switch k.String() {
	case "y", "Y":
	case "enter":
		if c.strict {
			return nil
		}
	case "n", "N", "esc":
		m.confirm, m.screen = nil, c.back
		return nil
	default:
		return nil
	}
	m.confirm, m.screen = nil, c.back
	return c.onYes(m)
}

// confirmView keeps the question visible and cuts the details when the
// terminal is too short for both.
func (m *model) confirmView() string {
	c := m.confirm
	help := []binding{{"enter/y", c.yes}, {"n/esc", "cancel"}}
	if c.strict {
		help[0].key = "y"
	}
	return m.page(c.word, c.subtitle, help, func(w, h int) string {
		question := textStyle.Width(w).Render(c.question)
		room := h - lipgloss.Height(question) - 1 // blank line above the question
		if c.details == nil || room < 1 {
			return question
		}
		lines := strings.Split(lipgloss.NewStyle().Width(w).Render(strings.Join(c.details(w), "\n")), "\n")
		if len(lines) > room {
			lines = append(lines[:room-1], mutedStyle.Render("…"))
		}
		return strings.Join(lines, "\n") + "\n\n" + question
	})
}

// pairs lays out labels and values in two columns, or each value below its
// label when a value does not fit beside the labels. A pair without a label
// continues the one above.
func pairs(width int, kv ...[2]string) []string {
	const labelWidth = 13
	stacked := false
	for _, p := range kv {
		stacked = stacked || labelWidth+ansi.StringWidth(p[1]) > width
	}
	var lines []string
	for _, p := range kv {
		switch {
		case !stacked:
			lines = append(lines, labelStyle.Width(labelWidth).Render(p[0])+p[1])
		case p[0] != "":
			lines = append(lines, labelStyle.Render(p[0]), p[1])
		default:
			lines = append(lines, p[1])
		}
	}
	return lines
}
