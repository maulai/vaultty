package sshclient

import (
	"time"

	"golang.org/x/term"
)

// watchResize polls the size of the console on fd, since Windows has no
// SIGWINCH, and calls onResize when it differs from the last known size,
// starting with w, h, until stop is called.
func watchResize(fd, w, h int, onResize func(w, h int)) (stop func()) {
	return background(func(done <-chan struct{}) {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
			}
			if nw, nh, err := term.GetSize(fd); err == nil && (nw != w || nh != h) {
				w, h = nw, nh
				onResize(w, h)
			}
		}
	})
}
