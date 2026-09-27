//go:build !linux

package router

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

func prepareExistingMerlinStartupScript(path string, expected []byte) (exists bool, retErr error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return true, fmt.Errorf("startup script is not a regular file: %s", path)
	}

	f, err := os.Open(path)
	if err != nil {
		return true, err
	}
	defer func() {
		if err := f.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()

	info, err = f.Stat()
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
	if !bytes.Equal(got, expected) {
		return true, fmt.Errorf("already installed with different startup script: %s", path)
	}
	if err := f.Chmod(0755); err != nil {
		return true, err
	}
	return true, nil
}
