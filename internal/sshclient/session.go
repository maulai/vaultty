package sshclient

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/maulai/vaultty/internal/console"
	"github.com/muesli/cancelreader"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	// pasteKey (ctrl+]) types the stored password, e.g. for sudo.
	pasteKey = 0x1d

	hint = " vaultty  ·  ctrl+] paste password  ·  exit or ctrl+d to disconnect "

	clearScreen = "\x1b[H\x1b[2J\x1b[3J"

	// resetTerminal undoes modes a remote program may have left behind:
	// scroll region, origin mode, autowrap, cursor, attributes, mouse
	// reporting, focus events, bracketed paste, kitty keyboard flags, xterm
	// modifyOtherKeys, keypad and cursor key modes.
	resetTerminal = "\x1b[r\x1b[?6l\x1b[?7h\x1b[?25h\x1b[0m" +
		"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1004l\x1b[?2004l" +
		"\x1b[<u\x1b[>4m\x1b>\x1b[?1l"

	keepaliveMaxMissed = 3
)

var (
	// ErrConnectionLost reports that a session ended because the server
	// stopped answering.
	ErrConnectionLost = errors.New("connection lost")

	keepaliveInterval = 30 * time.Second
)

// Session is an authenticated connection to a host. Run starts an
// interactive shell on the terminal; Session implements tea.ExecCommand.
type Session struct {
	client   *ssh.Client
	password string
	stdin    *os.File // nil means os.Stdin
	stdout   io.Writer
	stderr   io.Writer
}

// SetStdin keeps the terminal the TUI reads from: os.Stdin, or /dev/tty
// (CONIN$ on Windows) when stdin is redirected. Run reads that file itself,
// so that the read can be cancelled when the session ends.
func (s *Session) SetStdin(r io.Reader) {
	if f, ok := r.(*os.File); ok {
		s.stdin = f
	}
}

func (s *Session) SetStdout(w io.Writer) { s.stdout = w }

func (s *Session) SetStderr(w io.Writer) { s.stderr = w }

// Close closes the connection. Run closes it itself when the shell ends.
func (s *Session) Close() error { return s.client.Close() }

// Run runs an interactive shell until the remote side exits or the
// connection is lost. A remote exit status is not an error; a server that
// stopped answering is ErrConnectionLost.
func (s *Session) Run() (err error) {
	defer s.client.Close()
	// Started first, so that a connection that dies while the session is set
	// up ends it too.
	stopKeepalive, lost := keepalive(s.client, keepaliveInterval)
	defer func() {
		stopKeepalive()
		if lost() {
			err = ErrConnectionLost
		}
	}()
	sess, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()

	restoreVT, _ := console.EnableVT(os.Stdout)
	defer restoreVT()

	in := cmp.Or(s.stdin, os.Stdin)
	inFd, outFd := int(in.Fd()), int(os.Stdout.Fd())
	tty := term.IsTerminal(inFd)
	if tty {
		if state, err := term.MakeRaw(inFd); err == nil {
			defer term.Restore(inFd, state)
		}
	}

	// The size comes from stdout: on Windows only the screen buffer handle
	// knows it.
	w, h := 80, 24
	if cw, ch, err := term.GetSize(outFd); err == nil && cw > 0 && ch > 0 {
		w, h = cw, ch
	}
	io.WriteString(s.stdout, clearScreen+hintBanner(w))
	defer io.WriteString(s.stdout, resetTerminal)

	sess.Stdout, sess.Stderr = s.stdout, s.stderr
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := sess.RequestPty("xterm-256color", h, w, modes); err != nil {
		return err
	}

	if tty {
		restoreCP := utf8Input()
		defer restoreCP()
		stdin, err := sess.StdinPipe()
		if err != nil {
			return err
		}
		// A cancellable reader, so no pending read outlives the session and
		// swallows a key meant for the TUI.
		r, err := newInputReader(in)
		if err != nil {
			return err
		}
		stopInput := pump(stdin, r, s.password)
		defer stopInput()
	} else {
		sess.Stdin = in
	}

	stopResize := watchResize(outFd, w, h, func(w, h int) { _ = sess.WindowChange(h, w) })
	defer stopResize()

	if err := sess.Shell(); err != nil {
		return err
	}
	err = sess.Wait()
	_, exited := errors.AsType[*ssh.ExitError](err)
	_, missing := errors.AsType[*ssh.ExitMissingError](err)
	if exited || missing {
		return nil
	}
	return err
}

// pump feeds dst from r with pumpInput until stop is called. stop returns
// once r is closed and, if the pending read could be cancelled, the pump has
// ended.
func pump(dst io.Writer, r cancelreader.CancelReader, password string) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpInput(dst, r, password)
	}()
	return func() {
		// A read that could not be cancelled ends with the next key press;
		// waiting for it would block the TUI until then.
		if r.Cancel() {
			<-done
		}
		r.Close()
	}
}

// pumpInput copies src to dst until either fails and replaces every paste
// key with password.
func pumpInput(dst io.Writer, src io.Reader, password string) {
	key, paste := []byte{pasteKey}, []byte(password)
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if out := bytes.ReplaceAll(buf[:n], key, paste); len(out) > 0 {
			if _, err := dst.Write(out); err != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// hintBanner renders the hint as an inverted line exactly width cells wide.
func hintBanner(width int) string {
	text := ansi.Truncate(hint, width, "")
	text += strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
	return "\x1b[7m" + text + "\x1b[0m\r\n"
}

// keepalive pings the server every interval and closes the client when a
// ping stays unanswered for keepaliveMaxMissed intervals, which ends a
// session on a dead connection. lost reports whether it did.
func keepalive(c *ssh.Client, interval time.Duration) (stop func(), lost func() bool) {
	var closed atomic.Bool
	stop = background(func(done <-chan struct{}) {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		replies := make(chan error, 1)
		pending, missed := false, 0
		for {
			select {
			case <-done:
				return
			case err := <-replies:
				pending = false
				if err == nil {
					missed = 0
				}
			case <-ticker.C:
				if pending {
					missed++
					if missed >= keepaliveMaxMissed {
						closed.Store(true)
						c.Close()
						return
					}
					continue
				}
				pending = true
				go func() {
					_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
					replies <- err
				}()
			}
		}
	})
	return stop, closed.Load
}

// background runs f in a goroutine and returns a function that signals f to
// return and waits until it has.
func background(f func(done <-chan struct{})) (stop func()) {
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		f(done)
	}()
	return func() {
		close(done)
		<-finished
	}
}
