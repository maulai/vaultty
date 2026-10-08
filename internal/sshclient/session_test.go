package sshclient

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/maulai/vaultty/internal/vault"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"
)

func TestPumpInput(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		password string
		want     string
	}{
		{"plain", "ls -la\r", "pw", "ls -la\r"},
		{"paste", "sudo ls\r\x1d\r", "pw", "sudo ls\rpw\r"},
		{"paste only", "\x1d", "pw", "pw"},
		{"several pastes", "\x1d\x1da\x1d", "pw", "pwpwapw"},
		{"empty password sends nothing", "a\x1db", "", "ab"},
		{"empty password only", "\x1d", "", ""},
	}
	readers := map[string]func(io.Reader) io.Reader{
		"whole":    func(r io.Reader) io.Reader { return r },
		"bytewise": iotest.OneByteReader,
		"data+eof": iotest.DataErrReader,
	}
	for _, tt := range tests {
		for rname, wrap := range readers {
			t.Run(tt.name+"/"+rname, func(t *testing.T) {
				var out bytes.Buffer
				pumpInput(&out, wrap(strings.NewReader(tt.in)), tt.password)
				if got := out.String(); got != tt.want {
					t.Fatalf("got %q, want %q", got, tt.want)
				}
			})
		}
	}
}

type failingWriter struct{ writes int }

func (w *failingWriter) Write([]byte) (int, error) {
	w.writes++
	return 0, errors.New("closed")
}

type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) { return copy(p, "y"), nil }

func TestPumpInputStopsOnWriteError(t *testing.T) {
	var w failingWriter
	pumpInput(&w, endlessReader{}, "pw")
	if w.writes != 1 {
		t.Fatalf("%d writes, want 1", w.writes)
	}
}

func TestHintBanner(t *testing.T) {
	for _, width := range []int{1, 10, ansi.StringWidth(hint), 80, 200} {
		line := hintBanner(width)
		text, ok := strings.CutPrefix(line, "\x1b[7m")
		if ok {
			text, ok = strings.CutSuffix(text, "\x1b[0m\r\n")
		}
		if !ok {
			t.Fatalf("width %d: not an inverted line: %q", width, line)
		}
		if got := ansi.StringWidth(text); got != width {
			t.Errorf("width %d: banner is %d cells wide", width, got)
		}
		if !strings.HasPrefix(hint, text) && !strings.HasPrefix(text, hint) {
			t.Errorf("width %d: unexpected text %q", width, text)
		}
	}
}

// stuckReader is a cancelreader.CancelReader whose Read blocks until Cancel
// succeeds. It logs the order of events.
type stuckReader struct {
	cancellable bool
	unblock     chan struct{}
	mu          sync.Mutex
	events      []string
}

func (r *stuckReader) log(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *stuckReader) Read([]byte) (int, error) {
	<-r.unblock
	r.log("read returned")
	return 0, cancelreader.ErrCanceled
}

func (r *stuckReader) Cancel() bool {
	r.log("cancel")
	if r.cancellable {
		close(r.unblock)
	}
	return r.cancellable
}

func (r *stuckReader) Close() error {
	r.log("close")
	return nil
}

func TestPumpStop(t *testing.T) {
	tests := []struct {
		cancellable bool
		want        []string
	}{
		{true, []string{"cancel", "read returned", "close"}},
		// A read that cannot be cancelled is not waited for.
		{false, []string{"cancel", "close"}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint("cancellable ", tt.cancellable), func(t *testing.T) {
			r := &stuckReader{cancellable: tt.cancellable, unblock: make(chan struct{})}
			pump(io.Discard, r, "")()
			r.mu.Lock()
			got := slices.Clone(r.events)
			r.mu.Unlock()
			if !tt.cancellable {
				close(r.unblock)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("events = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRun(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal")
	}
	old := keepaliveInterval
	keepaliveInterval = 20 * time.Millisecond
	t.Cleanup(func() { keepaliveInterval = old })

	tests := []struct {
		name    string
		opts    serverOptions
		wantErr error
	}{
		{"exit status 0", serverOptions{exitStatus: 0}, nil},
		{"exit status 3", serverOptions{exitStatus: 3}, nil},
		{"server stops answering", serverOptions{silent: true, hang: true}, ErrConnectionLost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.opts.password, tt.opts.shell = "pw", true
			srv := startServer(t, tt.opts)
			host := srv.host
			host.Auth, host.Password = vault.AuthPassword, "pw"
			s, err := Dial(t.Context(), host, nil, "", srv.known)
			if err != nil {
				t.Fatal(err)
			}
			var out, stderr bytes.Buffer
			s.SetStdout(&out)
			s.SetStderr(&stderr)
			if err := s.Run(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run: err = %v, want %v", err, tt.wantErr)
			}
			got := out.String()
			if !strings.HasPrefix(got, clearScreen+"\x1b[7m") || !strings.HasSuffix(got, "hello\r\n"+resetTerminal) {
				t.Fatalf("output = %q", got)
			}
			if _, _, err := s.client.SendRequest("keepalive@openssh.com", true, nil); err == nil {
				t.Fatal("client still open after Run")
			}
		})
	}
}

// TestRunReadsSetStdin checks that a session reads the file passed to
// SetStdin, e.g. /dev/tty when stdin is redirected, not os.Stdin.
func TestRunReadsSetStdin(t *testing.T) {
	in, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	if _, err := w.WriteString("exit\r"); err != nil {
		t.Fatal(err)
	}
	w.Close()

	srv := startServer(t, serverOptions{password: "pw", shell: true, echo: true})
	host := srv.host
	host.Auth, host.Password = vault.AuthPassword, "pw"
	s, err := Dial(t.Context(), host, nil, "", srv.known)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s.SetStdin(in)
	s.SetStdout(&out)
	s.SetStderr(io.Discard)
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.HasSuffix(got, "hello\r\nexit\r"+resetTerminal) {
		t.Fatalf("output = %q", got)
	}
}

func TestKeepalive(t *testing.T) {
	tests := []struct {
		name       string
		silent     bool
		wantClosed bool
	}{
		{"answered", false, false},
		{"unanswered", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := startServer(t, serverOptions{password: "pw", silent: tt.silent})
			host := srv.host
			host.Auth, host.Password = vault.AuthPassword, "pw"
			s, err := Dial(t.Context(), host, nil, "", srv.known)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			stop, lost := keepalive(s.client, 50*time.Millisecond)
			defer stop()
			closed := make(chan struct{})
			go func() {
				s.client.Wait()
				close(closed)
			}()

			wait := 500 * time.Millisecond
			if tt.wantClosed {
				wait = 5 * time.Second
			}
			select {
			case <-closed:
				if !tt.wantClosed {
					t.Fatal("client closed although the server answers")
				}
			case <-time.After(wait):
				if tt.wantClosed {
					t.Fatal("client still open although the server never answers")
				}
			}
			if lost() != tt.wantClosed {
				t.Fatalf("lost() = %v, want %v", lost(), tt.wantClosed)
			}
		})
	}
}
