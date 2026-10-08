package sshclient

import (
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/muesli/cancelreader"
	"golang.org/x/sys/windows"
)

const cpUTF8 = 65001

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procPeekConsoleInputW = kernel32.NewProc("PeekConsoleInputW")
	procReadConsoleInputW = kernel32.NewProc("ReadConsoleInputW")
)

// utf8Input switches the console input code page to UTF-8 and returns a
// function that restores the previous one. The input reader reads the
// console with ReadFile, which delivers text in that code page, and the
// remote side expects UTF-8.
func utf8Input() (restore func()) {
	cp, err := windows.GetConsoleCP()
	if err != nil || windows.SetConsoleCP(cpUTF8) != nil {
		return func() {}
	}
	return func() { _ = windows.SetConsoleCP(cp) }
}

// inputRecord is INPUT_RECORD seen as a KEY_EVENT_RECORD.
type inputRecord struct {
	eventType uint16
	_         uint16
	keyDown   int32
	repeat    uint16
	vk        uint16
	scan      uint16
	char      uint16
	ctrl      uint32
}

// consoleReader reads the console with ReadFile, but only when a key press
// that ReadFile returns is at the front of the input buffer. It drops key
// releases and other records ReadFile would skip first, so a read never
// blocks in ReadFile and Cancel always ends it. Unlike cancelreader, it does
// not discard keys typed ahead.
type consoleReader struct {
	in, cancel windows.Handle
	canceled   atomic.Bool
}

func newInputReader(f *os.File) (cancelreader.CancelReader, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	return &consoleReader{in: windows.Handle(f.Fd()), cancel: ev}, nil
}

func (r *consoleReader) Read(p []byte) (int, error) {
	var recs [64]inputRecord
	for {
		if r.canceled.Load() {
			return 0, cancelreader.ErrCanceled
		}
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{r.in, r.cancel}, false, windows.INFINITE)
		if err != nil {
			return 0, err
		}
		if ev != windows.WAIT_OBJECT_0 {
			return 0, cancelreader.ErrCanceled
		}
		var n uint32
		if ok, _, err := procPeekConsoleInputW.Call(uintptr(r.in), uintptr(unsafe.Pointer(&recs[0])), uintptr(len(recs)), uintptr(unsafe.Pointer(&n))); ok == 0 {
			return 0, err
		}
		if n == 0 {
			continue // woken without input; ReadFile would block
		}
		skip := uint32(0)
		for _, rec := range recs[:n] {
			if rec.eventType == windows.KEY_EVENT && rec.keyDown != 0 && rec.char != 0 {
				break
			}
			skip++
		}
		if skip == 0 {
			err = windows.ReadFile(r.in, p, &n, nil)
			return int(n), err
		}
		if ok, _, err := procReadConsoleInputW.Call(uintptr(r.in), uintptr(unsafe.Pointer(&recs[0])), uintptr(skip), uintptr(unsafe.Pointer(&n))); ok == 0 {
			return 0, err
		}
	}
}

func (r *consoleReader) Cancel() bool {
	r.canceled.Store(true)
	return windows.SetEvent(r.cancel) == nil
}

func (r *consoleReader) Close() error { return windows.CloseHandle(r.cancel) }
