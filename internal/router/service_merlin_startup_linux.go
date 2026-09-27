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
		if err := replaceMerlinStartupScriptAtomically(path, expected, got, info); err != nil {
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

func replaceMerlinStartupScriptAtomically(path string, expected, legacy []byte, originalInfo os.FileInfo) (retErr error) {
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

	// Atomically exchange the prepared replacement with whatever currently
	// occupies path. This avoids the TOCTOU window of "Lstat then Rename": after
	// the exchange, tmpPath names the exact previous target and can be validated
	// by inode and bytes. If another actor changed/replaced the legacy script,
	// swap the files back and leave their content untouched.
	if err := unix.Renameat2(
		unix.AT_FDCWD, tmpPath,
		unix.AT_FDCWD, path,
		unix.RENAME_EXCHANGE,
	); err != nil {
		return fmt.Errorf("atomic startup-script exchange: %w", err)
	}

	rollbackExchange := func(cause error) error {
		if err := unix.Renameat2(
			unix.AT_FDCWD, tmpPath,
			unix.AT_FDCWD, path,
			unix.RENAME_EXCHANGE,
		); err != nil {
			return fmt.Errorf("%v; failed to restore startup script after exchange: %w", cause, err)
		}
		return cause
	}

	oldInfo, err := os.Lstat(tmpPath)
	if err != nil {
		return rollbackExchange(err)
	}
	if !oldInfo.Mode().IsRegular() || !os.SameFile(originalInfo, oldInfo) {
		return rollbackExchange(fmt.Errorf("startup script changed before migration publish: %s", path))
	}

	oldBytes, exists, err := readExistingMerlinStartupScript(tmpPath)
	if err != nil {
		return rollbackExchange(err)
	}
	if !exists || !bytes.Equal(oldBytes, legacy) {
		return rollbackExchange(fmt.Errorf("startup script contents changed before migration publish: %s", path))
	}

	// The exchange is now proven to have replaced exactly the ctrld-owned
	// legacy inode/bytes. Remove the old hard target and make the directory
	// updates durable.
	if err := os.Remove(tmpPath); err != nil {
		return err
	}
	if err := syncMerlinServiceDir(dir); err != nil {
		return err
	}
	return nil
}

