//go:build !windows

// Package console turns on escape sequence processing for Windows consoles.
package console

import "os"

// EnableVT is a no-op: Unix terminals always process escape sequences.
func EnableVT(*os.File) (restore func(), ok bool) { return func() {}, true }
