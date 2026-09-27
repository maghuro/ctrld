package merlin

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
)

func Test_merlinParsePostConf(t *testing.T) {
	origContent := "# foo"
	data := strings.Join([]string{
		dnsmasq.MerlinPostConfTmpl,
		"\n",
		dnsmasq.MerlinPostConfMarker,
		"\n",
	}, "\n")

	tests := []struct {
		name     string
		data     string
		expected string
	}{
		{"empty", "", ""},
		{"no ctrld", origContent, origContent},
		{"ctrld with data", data + origContent, origContent},
		{"ctrld without data", data, ""},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			//t.Parallel()
			if got := merlinParsePostConf([]byte(tc.data)); !bytes.Equal(got, []byte(tc.expected)) {
				t.Errorf("unexpected result, want: %q, got: %q", tc.expected, string(got))
			}
		})
	}
}


func Test_merlinParsePostConfMarkedBlock(t *testing.T) {
	input := "#!/bin/sh\n\n# BEGIN ctrld\necho ctrld\n# END ctrld\n\necho custom\n"
	want := "#!/bin/sh\n\necho custom"

	if got := string(merlinParsePostConf([]byte(input))); got != want {
		t.Fatalf("unexpected result, want %q, got %q", want, got)
	}
}

func Test_merlinUpsertPostConfPreservesExistingContent(t *testing.T) {
	orig := []byte("#!/bin/sh\n\necho before\necho after\n")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")

	got := merlinUpsertPostConf(orig, block)

	if bytes.Count(got, []byte(dnsmasq.MerlinPostConfBeginMarker)) != 1 {
		t.Fatalf("expected exactly one ctrld block, got:\n%s", got)
	}
	if !bytes.Contains(got, []byte("echo before\necho after")) {
		t.Fatalf("existing hook content was not preserved:\n%s", got)
	}
	if !bytes.HasPrefix(got, []byte("#!/bin/sh\n")) {
		t.Fatalf("existing shebang was not preserved:\n%s", got)
	}

	gotAgain := merlinUpsertPostConf(got, block)
	if !bytes.Equal(got, gotAgain) {
		t.Fatalf("upsert is not idempotent:\nfirst:\n%s\nsecond:\n%s", got, gotAgain)
	}
}

func Test_merlinPostConfDoesNotExitHostHook(t *testing.T) {
	if strings.Contains(dnsmasq.MerlinPostConfTmpl, "exit 0") {
		t.Fatal("ctrld postconf block must not terminate the enclosing Merlin hook")
	}
}
