//go:build unix

package sshclient

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// watchResize calls onResize when the size of the terminal on fd differs from
// the last known size, starting with w, h, after every SIGWINCH until stop is
// called.
func watchResize(fd, w, h int, onResize func(w, h int)) (stop func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	// Check once for a resize that happened before Notify.
	select {
	case sig <- syscall.SIGWINCH:
	default:
	}
	stopWatching := background(func(done <-chan struct{}) {
		for {
			select {
			case <-done:
				return
			case <-sig:
			}
			if nw, nh, err := term.GetSize(fd); err == nil && (nw != w || nh != h) {
				w, h = nw, nh
				onResize(w, h)
			}
		}
	})
	return func() {
		signal.Stop(sig)
		stopWatching()
	}
}
