package tui

import (
	"errors"
	"fmt"
	"os"
	"slices"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/maulai/vaultty/internal/config"
	"github.com/maulai/vaultty/internal/console"
	"golang.org/x/term"
)

// The XTWINOPS title stack: save the window title and restore it on exit.
// Terminals without it ignore the sequences.
const (
	pushTitle = "\x1b[22;0t"
	popTitle  = "\x1b[23;0t"
)

// Run shows the user interface until the user quits. Changes not yet on disk
// when the program ends are written before Run returns.
func Run(cfg *config.Config, firstRun bool, version string) error {
	writeTerminal(pushTitle)
	defer writeTerminal(popTitle)

	final, err := tea.NewProgram(newModel(cfg, firstRun, version), tea.WithAltScreen()).Run()
	if m, ok := final.(model); ok {
		err = errors.Join(err, m.shutdown())
	}
	return err
}

// shutdown writes the changes not yet on disk and wipes the keys, also of
// locked vaults whose stores may still be closing in the background.
func (m *model) shutdown() error {
	stores := slices.Clone(m.closing)
	if m.v != nil {
		stores = append(stores, m.v.store)
	}
	var err error
	for _, st := range stores {
		if ferr := st.Flush(); ferr != nil {
			err = errors.Join(err, fmt.Errorf("save vault: %w", ferr))
		}
		st.Close()
	}
	return err
}

// writeTerminal writes an escape sequence, but only to a terminal that
// processes it.
func writeTerminal(seq string) {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return
	}
	restore, ok := console.EnableVT(os.Stdout)
	defer restore()
	if ok {
		os.Stdout.WriteString(seq)
	}
}
