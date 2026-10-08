// Package console turns on escape sequence processing for Windows consoles.
package console

import (
	"os"

	"golang.org/x/sys/windows"
)

// EnableVT enables virtual terminal processing on f and returns a function
// that restores the previous console mode. Windows Terminal always has it; the
// classic console does not.
func EnableVT(f *os.File) (restore func(), ok bool) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return func() {}, false
	}
	if err := windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return func() {}, false
	}
	return func() { _ = windows.SetConsoleMode(h, mode) }, true
}
