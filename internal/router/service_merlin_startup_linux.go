//go:build linux

package router

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func prepareExistingMerlinStartupScript(path string, expected, legacy []byte) (exists bool, retErr error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return false, nil
		}
		if err == unix.ELOOP {
			return true, fmt.Errorf("startup script is not a regular file: %s", path)
		}
		return false, err
	}

	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return true, fmt.Errorf("could not wrap startup script descriptor: %s", path)
	}
	defer func() {
		if err := f.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()

	info, err := f.Stat()
	if err != nil {
		return true, err
	}
	if !info.Mode().IsRegular() {
		return true, fmt.Errorf("startup script is not a regular file: %s", path)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		return true, err
	}
	needsMigration := bytes.Equal(got, legacy) && !bytes.Equal(got, expected)
	if !bytes.Equal(got, expected) && !needsMigration {
		return true, fmt.Errorf("already installed with different startup script: %s", path)
	}

	// Keep validation, content comparison, optional legacy migration and chmod
	// pinned to the same inode. O_NOFOLLOW prevents a pathname race from
	// redirecting privileged operations through a symlink.
	if needsMigration {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return true, err
		}
		if err := f.Truncate(0); err != nil {
			return true, err
		}
		if _, err := f.Write(expected); err != nil {
			return true, err
		}
	}
	if err := f.Chmod(0755); err != nil {
		return true, err
	}
	if err := f.Sync(); err != nil {
		return true, err
	}

	// Confirm the pathname still names the same inode we validated/migrated.
	// If another lifecycle operation replaced it, leave that replacement alone
	// and report the race to the caller.
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return true, err
	}
	if !os.SameFile(info, pathInfo) {
		return true, fmt.Errorf("startup script changed during preparation: %s", path)
	}
	return true, nil
}
