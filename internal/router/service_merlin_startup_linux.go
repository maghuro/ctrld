//go:build linux

package router

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readExistingMerlinStartupScript(path string) ([]byte, bool, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		if err == unix.ENOENT {
			return nil, false, nil
		}
		if err == unix.ELOOP {
			return nil, true, fmt.Errorf("startup script is not a regular file: %s", path)
		}
		return nil, false, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, true, fmt.Errorf("could not wrap startup script descriptor: %s", path)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, true, err
	}
	if !info.Mode().IsRegular() {
		return nil, true, fmt.Errorf("startup script is not a regular file: %s", path)
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, true, err
	}
	return buf, true, nil
}

func prepareExistingMerlinStartupScript(path string, expected, legacy []byte) (exists bool, retErr error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
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

	if needsMigration {
		// Build the replacement completely in the same directory and publish it
		// with rename(2). The legacy inode is never truncated, so ENOSPC/EIO while
		// writing the new script leaves the previously working service intact.
		if err := replaceMerlinStartupScriptAtomically(path, expected, info); err != nil {
			return true, err
		}
		return true, nil
	}

	// Current script: mode/content validation stays descriptor-pinned.
	if err := f.Chmod(0755); err != nil {
		return true, err
	}
	if err := f.Sync(); err != nil {
		return true, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return true, err
	}
	if !os.SameFile(info, pathInfo) {
		return true, fmt.Errorf("startup script changed during preparation: %s", path)
	}
	return true, nil
}

func replaceMerlinStartupScriptAtomically(path string, expected []byte, originalInfo os.FileInfo) (retErr error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".ctrld-migrate-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0755); err != nil {
		return err
	}
	if _, err := tmp.Write(expected); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Revalidate ownership immediately before publication. The service-level
	// flock serializes ctrld lifecycle operations; this check additionally
	// refuses to overwrite a pathname another actor replaced during migration.
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !os.SameFile(originalInfo, pathInfo) {
		return fmt.Errorf("startup script changed before migration publish: %s", path)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := syncMerlinServiceDir(dir); err != nil {
		return err
	}
	return nil
}
