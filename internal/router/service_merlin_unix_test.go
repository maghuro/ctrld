//go:build !windows

package router

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCreateMerlinSharedHookStubIgnoresRestrictiveUmask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "services-start")

	oldUmask := syscall.Umask(0777)
	defer syscall.Umask(oldUmask)

	if err := createMerlinSharedHookStub(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("shared hook mode = %o, want 755", got)
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf) != "#!/bin/sh\n" {
		t.Fatalf("shared hook contents = %q", buf)
	}
}
