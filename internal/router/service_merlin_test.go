package router

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kardianos/service"
)

func TestMerlinServiceScriptValidatesPidOwnership(t *testing.T) {
	if strings.Contains(merlinSvcScript, "ps | grep") {
		t.Fatal("Merlin service status must not trust PID existence alone")
	}
	for _, want := range []string{
		`case "$pid" in`,
		`[ -r "/proc/$pid/cmdline" ]`,
		`tr '\000' ' '`,
		`"$exe"|"$exe "*`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service script missing PID ownership check %q", want)
		}
	}
}

func TestMerlinServiceRestartStopsBeforeStarting(t *testing.T) {
	if !strings.Contains(merlinSvcScript, `"$0" stop || exit $?`) {
		t.Fatal("restart must not start a second instance when stop fails")
	}
}

func TestMerlinServiceHookEditorIsIdempotent(t *testing.T) {
	for _, want := range []string{
		`if grep -qxF "$line" "$file"; then`,
		`grep_status=$?`,
		`[ "$grep_status" -eq 1 ] || exit "$grep_status"`,
		`pc_append "$line" "$file" || exit $?`,
		`printf 'added\n'`,
	} {
		if !strings.Contains(merlinAddLineToScript, want) {
			t.Fatalf("hook editor missing idempotent append signal %q", want)
		}
	}
	for _, script := range []string{merlinAddLineToScript, merlinRemoveLineFromScript} {
		if !strings.Contains(script, `sed -i "/^$pattern$/d" "$file"`) {
			t.Fatal("hook removal must match only ctrld's complete line")
		}
	}
	if strings.Contains(merlinAddLineToScript, `pc_delete "$line" "$file"`) {
		t.Fatal("install path must not destructively delete a working hook before append")
	}
}

func TestMerlinServiceTemplateRendersExecutableIdentity(t *testing.T) {
	s := &merlinSvc{
		Config: &service.Config{
			Name:       "ctrld",
			Executable: "/jffs/controld/ctrld",
			Arguments:  []string{"run", "--cd", "example"},
		},
	}
	var buf bytes.Buffer
	if err := s.template().Execute(&buf, struct {
		*service.Config
		Path string
	}{s.Config, s.Config.Executable}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	for _, want := range []string{
		`exe='/jffs/controld/ctrld'`,
		`'/jffs/controld/ctrld' 'run' '--cd' 'example' &`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered Merlin startup script missing %q", want)
		}
	}
}

func TestMerlinServiceTemplatePreservesArgumentBoundaries(t *testing.T) {
	s := &merlinSvc{
		Config: &service.Config{
			Name:       "ctrld",
			Executable: "/jffs/controld/ctrld",
			Arguments:  []string{"run", "--log", "/jffs/log dir/it's.log"},
		},
	}
	var buf bytes.Buffer
	if err := s.template().Execute(&buf, struct {
		*service.Config
		Path string
	}{s.Config, s.Config.Executable}); err != nil {
		t.Fatal(err)
	}
	want := `'/jffs/controld/ctrld' 'run' '--log' '/jffs/log dir/it'"'"'s.log' &`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("rendered command lost shell argument boundaries:\nwant substring: %q\ngot:\n%s", want, buf.String())
	}
}


func TestMerlinServiceStartWaitsForChildExec(t *testing.T) {
	for _, want := range []string{
		"for _ in 1 2 3 4 5; do",
		"if is_running; then",
		"sleep 1",
		`[ "$started" -ne 1 ]`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service start is missing exec-wait safeguard %q", want)
		}
	}
}


func TestMerlinServiceStatusTreatsStoppedAsState(t *testing.T) {
	status, err := merlinServiceStatus([]byte("stopped\n"), os.ErrProcessDone)
	if err != nil {
		t.Fatalf("stopped status returned error: %v", err)
	}
	if status != service.StatusStopped {
		t.Fatalf("status = %v, want %v", status, service.StatusStopped)
	}
}

func TestMerlinServiceStatusRejectsUnexpectedOutput(t *testing.T) {
	if _, err := merlinServiceStatus([]byte("mystery\n"), nil); err == nil {
		t.Fatal("expected unexpected status output to return an error")
	}
}


func TestWriteMerlinStartupScriptPublishesAndPreservesMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows filesystems do not expose POSIX executable mode semantics")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	want := []byte("#!/bin/sh\necho ok\n")

	published, err := writeMerlinStartupScript(path, want, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if !published {
		t.Fatal("expected startup script to be published")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("startup script contents mismatch: got %q want %q", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0755 {
		t.Fatalf("startup script mode = %o, want 755", fi.Mode().Perm())
	}
}

func TestWriteMerlinStartupScriptDoesNotClobberExistingTarget(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctrld.startup")
	original := []byte("user-owned\n")
	if err := os.WriteFile(path, original, 0700); err != nil {
		t.Fatal(err)
	}

	published, err := writeMerlinStartupScript(path, []byte("ctrld-owned\n"), 0755)
	if err == nil {
		t.Fatal("expected publication to fail for existing target")
	}
	if published {
		t.Fatal("existing target must not be reported as ctrld-published")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("existing target was modified: got %q want %q", got, original)
	}
}


func TestMerlinServiceEventValidatesDnsmasqPidOwnership(t *testing.T) {
	for _, want := range []string{
		`case "$dnsmasq_pid" in`,
		`[ -r "/proc/$dnsmasq_pid/cmdline" ]`,
		`tr '\000' '\n'`,
		`dnsmasq|*/dnsmasq) kill "$dnsmasq_pid"`,
	} {
		if !strings.Contains(merlinSvcScript, want) {
			t.Fatalf("Merlin service_event missing dnsmasq PID ownership check %q", want)
		}
	}
}


func TestValidateMerlinSharedHookPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Merlin shared hooks are POSIX shell files and executable-bit checks are Unix-specific")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "services-start")

	exists, err := validateMerlinSharedHookPath(path, true)
	if err != nil || exists {
		t.Fatalf("missing hook = (%v, %v), want (false, nil)", exists, err)
	}

	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := validateMerlinSharedHookPath(path, true); err == nil {
		t.Fatal("expected non-executable shared hook to be rejected")
	}
	if exists, err := validateMerlinSharedHookPath(path, false); err != nil || !exists {
		t.Fatalf("regular non-executable hook should be editable for uninstall: (%v, %v)", exists, err)
	}

	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if exists, err := validateMerlinSharedHookPath(path, true); err != nil || !exists {
		t.Fatalf("executable shared hook rejected: (%v, %v)", exists, err)
	}

	link := filepath.Join(dir, "services-start-link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := validateMerlinSharedHookPath(link, false); err == nil {
			t.Fatal("expected shared-hook symlink to be rejected")
		}
	}
}


func TestMerlinStartupHookLinesQuoteConfigPath(t *testing.T) {
	start, event := merlinStartupHookLines("/jffs/my dir/it's ctrld.startup")
	wantPrefix := `'/jffs/my dir/it'"'"'s ctrld.startup'`
	if start != wantPrefix+" start" {
		t.Fatalf("start hook = %q", start)
	}
	if event != wantPrefix+` service_event "$1" "$2"` {
		t.Fatalf("service-event hook = %q", event)
	}
}


func TestMerlinLegacyStartupHookLinesRemainRemovable(t *testing.T) {
	path := "/jffs/controld/ctrld.startup"
	start, event := merlinLegacyStartupHookLines(path)
	if start != path+" start" {
		t.Fatalf("legacy start hook = %q", start)
	}
	if event != path+` service_event "$1" "$2"` {
		t.Fatalf("legacy service-event hook = %q", event)
	}
}


func TestPrepareExistingMerlinStartupScriptRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "ctrld.startup")
	if err := os.WriteFile(target, []byte("private\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if exists, err := prepareExistingMerlinStartupScript(link, []byte("private\n")); err == nil || !exists {
		t.Fatalf("symlink startup script = (exists %v, err %v), want exists=true and error", exists, err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "private\n" {
		t.Fatalf("symlink target was modified: %q", got)
	}
}

func TestPrepareExistingMerlinStartupScriptRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.startup")
	want := []byte("#!/bin/sh\n")
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	exists, err := prepareExistingMerlinStartupScript(path, want)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("regular startup script reported missing")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("regular startup script = %q, want %q", got, want)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if gotMode := info.Mode().Perm(); gotMode != 0755 {
			t.Fatalf("regular startup script mode = %o, want 755", gotMode)
		}
	}
}

func TestPrepareExistingMerlinStartupScriptMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctrld.startup")
	exists, err := prepareExistingMerlinStartupScript(path, []byte("#!/bin/sh\n"))
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("missing startup script reported as existing")
	}
}
