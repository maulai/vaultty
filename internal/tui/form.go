package tui

import (
	"fmt"
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// form is a column of fields of which one has the focus. id is the item the
// form edits, empty when it adds a new one.
type form struct {
	id     string
	fields []field
	focus  int
}

// field is a text input, or a choice between options when choice is set.
type field struct {
	label, desc string
	input       textinput.Model
	choice      bool
	options     []option
	selected    int
	hidden      bool
}

type option struct{ value, label string }

func newForm(id string, fields ...field) *form {
	f := &form{id: id, fields: fields}
	f.focusOn(0)
	return f
}

func textField(label, desc, value string, secret bool) field {
	return field{label: label, desc: desc, input: newInput(value, secret)}
}

func choiceField(label, desc string, options []option, value string) field {
	fl := field{label: label, desc: desc, choice: true, options: options}
	fl.choose(value)
	return fl
}

// newInput returns a text input in the app style. The cursor does not blink
// and the clipboard is not read: terminals deliver a paste as key input.
func newInput(value string, secret bool) textinput.Model {
	in := textinput.New()
	in.Prompt = ""
	in.TextStyle = textStyle
	in.PlaceholderStyle = mutedStyle
	in.Cursor.Style = lipgloss.NewStyle().Foreground(colorAccent)
	in.Cursor.SetMode(cursor.CursorStatic)
	in.KeyMap.Paste.SetEnabled(false)
	if secret {
		in.EchoMode = textinput.EchoPassword
		in.EchoCharacter = '•'
	}
	in.SetValue(value)
	return in
}

// updateInput applies a key to a text input in a column of the given width.
func updateInput(in *textinput.Model, k tea.KeyMsg, width int) {
	in.Width = inputWidth(width)
	*in, _ = in.Update(k) // no command: the cursor is static and the clipboard unused
}

// value returns the text of a text field or the value of the selected option.
func (f *form) value(i int) string {
	fl := &f.fields[i]
	if !fl.choice {
		return fl.input.Value()
	}
	o, _ := cursorItem(fl.options, fl.selected)
	return o.value
}

func (fl *field) choose(value string) {
	if i := slices.IndexFunc(fl.options, func(o option) bool { return o.value == value }); i >= 0 {
		fl.selected = i
	}
}

// update moves the focus with tab and the up and down keys, changes a choice
// with left, right and space, and passes other keys to the focused text
// input.
func (f *form) update(k tea.KeyMsg, width int) {
	fl := &f.fields[f.focus]
	switch key := k.String(); {
	case key == "tab" || key == "down":
		f.move(1)
	case key == "shift+tab" || key == "up":
		f.move(-1)
	case fl.choice && key == "left":
		fl.cycle(-1)
	case fl.choice && (key == "right" || key == " "):
		fl.cycle(1)
	case !fl.choice:
		updateInput(&fl.input, k, width)
	}
}

func (fl *field) cycle(d int) {
	if n := len(fl.options); n > 0 {
		fl.selected = (fl.selected + d + n) % n
	}
}

// move focuses the next visible field in direction d, wrapping around.
func (f *form) move(d int) {
	n, i := len(f.fields), f.focus
	for range n {
		i = (i + d + n) % n
		if !f.fields[i].hidden {
			break
		}
	}
	f.focusOn(i)
}

func (f *form) focusOn(i int) {
	if fl := &f.fields[f.focus]; !fl.choice {
		fl.input.Blur()
	}
	f.focus = i
	if fl := &f.fields[i]; !fl.choice {
		fl.input.Focus()
	}
}

// view renders the visible fields into at most height lines: separated by
// blank lines when there is room, else compact, else as a window around the
// focused field.
func (f *form) view(width, height int) string {
	var shown []int
	for i := range f.fields {
		if !f.fields[i].hidden {
			shown = append(shown, i)
		}
	}
	gap := "\n"
	if len(shown)*3-1 <= height {
		gap = "\n\n"
	}
	scroll := len(shown)*2 > height
	start, end := 0, len(shown)
	if scroll {
		start, end = window(len(shown), slices.Index(shown, f.focus), max((height-2)/2, 1))
	}
	var parts []string
	if scroll {
		parts = append(parts, marker(start > 0, "↑ more"))
	}
	for _, i := range shown[start:end] {
		parts = append(parts, f.fieldView(i, width))
	}
	if scroll {
		parts = append(parts, marker(end < len(shown), "↓ more"))
	}
	return strings.Join(parts, gap)
}

// fieldView renders the label, with the description while focused, and
// below it the input or the choice.
func (f *form) fieldView(i, width int) string {
	fl := &f.fields[i]
	focused := i == f.focus
	head := labelStyle.Render(fl.label)
	if focused && fl.desc != "" {
		head += "  " + mutedStyle.Render(fl.desc)
	}
	head = ansi.Truncate(head, width, "…")
	if !fl.choice {
		return head + "\n" + inputView(fl.input, width, focused)
	}
	return head + "\n" + bar(focused) + fl.choiceView(width-2)
}

// choiceView shows all options as chips, or only the selected one when the
// chips do not fit.
func (fl *field) choiceView(width int) string {
	if len(fl.options) == 0 {
		return mutedStyle.Render("none")
	}
	labels := make([]string, len(fl.options))
	for i, o := range fl.options {
		labels[i] = o.label
	}
	if s := segmented(labels, fl.selected); lipgloss.Width(s) <= width {
		return s
	}
	s := fmt.Sprintf("‹ %s ›  %d/%d", labels[fl.selected], fl.selected+1, len(labels))
	return textStyle.Render(ansi.Truncate(s, width, "…"))
}

// formHelp returns the help bar of a form whose enter key does action.
func formHelp(f *form, action string) []binding {
	var help []binding
	if len(f.fields) > 1 {
		help = append(help, binding{"tab/↑↓", "field"})
	}
	if slices.ContainsFunc(f.fields, func(fl field) bool { return fl.choice }) {
		help = append(help, binding{"←/→", "choose"})
	}
	return append(help, binding{"enter", action}, binding{"esc", "cancel"})
}
