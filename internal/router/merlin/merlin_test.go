package merlin

import (
	"bytes"
	"os"
	"path/filepath"
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


func Test_merlinLegacyMigrationPreservesPrependedContent(t *testing.T) {
	legacy := strings.Join([]string{
		"echo addon-before",
		dnsmasq.CtrldMarker,
		"#!/bin/sh",
		"echo ctrld-legacy",
		dnsmasq.MerlinPostConfMarker,
		"echo addon-after",
	}, "\n")
	block := []byte("# BEGIN ctrld\necho ctrld-new\n# END ctrld")

	got := string(merlinUpsertPostConf([]byte(legacy), block))
	want := "echo addon-before\n# BEGIN ctrld\necho ctrld-new\n# END ctrld\necho addon-after"
	if got != want {
		t.Fatalf("legacy migration changed unrelated content or position:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func Test_merlinUpsertPostConfKeepsExistingBlockPosition(t *testing.T) {
	input := []byte("#!/bin/sh\n\necho addon-before\n# BEGIN ctrld\necho old\n# END ctrld\necho addon-after\n")
	block := []byte("# BEGIN ctrld\necho new\n# END ctrld")

	got := string(merlinUpsertPostConf(input, block))
	want := "#!/bin/sh\n\necho addon-before\n# BEGIN ctrld\necho new\n# END ctrld\necho addon-after\n"
	if got != want {
		t.Fatalf("managed block moved relative to addon content:\nwant:\n%s\ngot:\n%s", want, got)
	}
}

func Test_merlinParsePostConfPreservesLegacyPrefixAndSuffix(t *testing.T) {
	input := strings.Join([]string{
		"echo addon-before",
		dnsmasq.CtrldMarker,
		"#!/bin/sh",
		"echo ctrld-legacy",
		dnsmasq.MerlinPostConfMarker,
		"echo addon-after",
	}, "\n")
	want := "echo addon-before\necho addon-after"

	if got := string(merlinParsePostConf([]byte(input))); got != want {
		t.Fatalf("legacy cleanup changed unrelated content:\nwant: %q\ngot:  %q", want, got)
	}
}


func Test_cleanupDnsmasqPostconfPreservesPreexistingStub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	installed := merlinUpsertPostConf([]byte("#!/bin/sh\n"), block)
	if err := os.WriteFile(path, installed, 0750); err != nil {
		t.Fatal(err)
	}

	if err := cleanupDnsmasqPostconf(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("pre-existing hook stub was removed: %v", err)
	}
	if string(got) != "#!/bin/sh" {
		t.Fatalf("unexpected restored stub: %q", got)
	}
}

func Test_cleanupDnsmasqPostconfRemovesCtrldCreatedStub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dnsmasq.postconf")
	block := []byte("# BEGIN ctrld\necho managed\n# END ctrld")
	if err := os.WriteFile(path, merlinUpsertPostConf(nil, block), 0750); err != nil {
		t.Fatal(err)
	}
	marker := merlinPostConfCreatedMarker(path)
	if err := os.WriteFile(marker, []byte("created\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := cleanupDnsmasqPostconf(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("ctrld-created hook still exists: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("ctrld-created marker still exists: %v", err)
	}
}

func Test_atomicWriteFilePreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "dnsmasq.postconf")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", link); err != nil {
		t.Fatal(err)
	}

	if err := atomicWriteFile(link, []byte("new"), 0750); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("atomicWriteFile replaced the symlink instead of its target")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("target content = %q, want %q", got, "new")
	}
}
