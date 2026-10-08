//go:build unix

package sshclient

import (
	"os"

	"github.com/muesli/cancelreader"
)

// utf8Input does nothing: Unix terminals deliver input in the encoding the
// terminal emulator uses, without a separate code page.
func utf8Input() (restore func()) { return func() {} }

func newInputReader(f *os.File) (cancelreader.CancelReader, error) {
	return cancelreader.NewReader(f)
}
