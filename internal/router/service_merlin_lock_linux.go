//go:build linux

package router

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const merlinServiceLockPath = "/tmp/ctrld-merlin-service.lock"

func withMerlinServiceLock(fn func() error) error {
	f, err := os.OpenFile(merlinServiceLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock Merlin service lifecycle: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)

	return fn()
}
