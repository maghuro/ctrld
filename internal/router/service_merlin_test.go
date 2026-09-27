package router

import (
	"bytes"
	"os"
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
	deleteAt := strings.Index(merlinAddLineToScript, `pc_delete "$line" "$file"`)
	appendAt := strings.Index(merlinAddLineToScript, `pc_append "$line" "$file"`)
	if deleteAt < 0 || appendAt < 0 || deleteAt > appendAt {
		t.Fatal("hook editor must delete an existing ctrld line before appending it")
	}
	if !strings.Contains(merlinAddLineToScript, `[ "$mode" = "remove" ] ||`) {
		t.Fatal("hook editor must support remove-only rollback mode")
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
		`exe="/jffs/controld/ctrld"`,
		`cmd="/jffs/controld/ctrld run --cd example"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered Merlin startup script missing %q", want)
		}
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
