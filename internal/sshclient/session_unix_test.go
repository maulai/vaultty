//go:build unix

package sshclient

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/muesli/cancelreader"
)

// TestPumpLeavesLaterInput checks that no read outlives stop: input that
// arrives afterwards stays in the file for the next reader.
func TestPumpLeavesLaterInput(t *testing.T) {
	in, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	defer w.Close()
	r, err := cancelreader.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	out, outW := io.Pipe()
	stop := pump(outW, r, "pw")

	buf := make([]byte, 2)
	if _, err := w.Write([]byte{pasteKey}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(out, buf); err != nil || string(buf) != "pw" {
		t.Fatalf("pumped %q, %v; want \"pw\"", buf, err)
	}
	stop()

	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := in.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(in, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("read %q, %v after stop; want \"ok\"", buf, err)
	}
}
