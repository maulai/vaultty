package sshclient

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/muesli/cancelreader"
	"golang.org/x/sys/windows"
	"golang.org/x/term"
)

func TestUTF8Input(t *testing.T) {
	before, err := windows.GetConsoleCP()
	if err != nil {
		t.Skip("no console")
	}
	restore := utf8Input()
	during, _ := windows.GetConsoleCP()
	restore()
	after, _ := windows.GetConsoleCP()
	if during != cpUTF8 || after != before {
		t.Fatalf("code page before %d, during %d, after %d", before, during, after)
	}
}

// TestConsoleReader checks that the reader keeps keys typed ahead, that
// Cancel ends a read waiting after a key release, and that no read outlives
// Cancel to take the next key. It runs again in a console of its own without
// a window, where it can type with WriteConsoleInputW.
func TestConsoleReader(t *testing.T) {
	if os.Getenv("VAULTTY_CONSOLE_TEST") == "" {
		// A read stuck in ReadFile can keep the child from exiting.
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConsoleReader$", "-test.v")
		cmd.Env = append(os.Environ(), "VAULTTY_CONSOLE_TEST=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
		out, err := cmd.CombinedOutput()
		switch {
		case err != nil:
			t.Fatalf("%v\n%s", err, out)
		case bytes.Contains(out, []byte("--- SKIP")):
			t.Skipf("%s", out)
		}
		return
	}

	h, err := windows.CreateFile(windows.StringToUTF16Ptr("CONIN$"), windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Skip("no console:", err)
	}
	f := os.NewFile(uintptr(h), "CONIN$")
	defer f.Close()
	state, err := term.MakeRaw(int(h))
	if err != nil {
		t.Fatal(err)
	}
	defer term.Restore(int(h), state)

	writeInput := kernel32.NewProc("WriteConsoleInputW")
	key := func(c rune, down bool) {
		rec := inputRecord{eventType: windows.KEY_EVENT, repeat: 1, char: uint16(c)}
		if down {
			rec.keyDown = 1
		}
		var n uint32
		if ok, _, err := writeInput.Call(uintptr(h), uintptr(unsafe.Pointer(&rec)), 1, uintptr(unsafe.Pointer(&n))); ok == 0 {
			t.Fatal(err)
		}
	}
	type result struct {
		s   string
		err error
	}
	read := func(r cancelreader.CancelReader) <-chan result {
		c := make(chan result, 1)
		go func() {
			buf := make([]byte, 16)
			n, err := r.Read(buf)
			c <- result{string(buf[:n]), err}
		}()
		return c
	}
	wait := func(c <-chan result) result {
		t.Helper()
		select {
		case res := <-c:
			return res
		case <-time.After(5 * time.Second):
			t.Fatal("Read did not return")
			return result{}
		}
	}

	key('a', true) // typed before the session reads
	key('a', false)
	r, err := newInputReader(f)
	if err != nil {
		t.Fatal(err)
	}
	if res := wait(read(r)); res.err != nil || res.s != "a" {
		t.Fatalf("Read = %q, %v; want the key typed ahead", res.s, res.err)
	}

	key('x', false) // the release of the last key of the session
	c := read(r)
	time.Sleep(100 * time.Millisecond)
	if !r.Cancel() {
		t.Fatal("Cancel failed")
	}
	if res := wait(c); !errors.Is(res.err, cancelreader.ErrCanceled) {
		t.Fatalf("Read after Cancel = %q, %v", res.s, res.err)
	}
	r.Close()

	key('b', true) // meant for the next reader
	next, err := newInputReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if res := wait(read(next)); res.err != nil || res.s != "b" {
		t.Fatalf("next Read = %q, %v; want the key typed after Cancel", res.s, res.err)
	}
}
