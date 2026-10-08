// Package atomicfile replaces files so that readers see either the old or the
// new content, never a partial write.
package atomicfile

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// WriteFile writes data to a temporary file next to path, flushes it to disk
// and renames it over path. It never creates directories, so a missing
// directory (for example an unmounted network share) is an error. A symlink
// at path is followed: the file it points to is replaced, not the link, and
// a dangling link is an error.
func WriteFile(path string, data []byte, perm fs.FileMode) (err error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		if path, err = filepath.EvalSymlinks(path); err != nil {
			return err
		}
	}
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	f, err := os.CreateTemp(dir, "."+base+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return rename(tmp, path)
}

// rename retries briefly on Windows, where virus scanners and sync clients
// hold short-lived handles on freshly written files.
func rename(from, to string) error {
	err := os.Rename(from, to)
	for i := 0; err != nil && runtime.GOOS == "windows" && i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		err = os.Rename(from, to)
	}
	return err
}
