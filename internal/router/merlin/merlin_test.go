package merlin

import (
	"bytes"
	"errors"
	"time"
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


func Test_waitUntilReady(t *testing.T) {
	calls := 0
	err := waitUntil(100*time.Millisecond, time.Millisecond, func() (bool, error) {
		calls++
		return calls >= 2, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls < 2 {
		t.Fatalf("probe calls = %d, want at least 2", calls)
	}
}

func Test_waitUntilPropagatesProbeError(t *testing.T) {
	want := errors.New("probe failed")
	err := waitUntil(100*time.Millisecond, time.Millisecond, func() (bool, error) {
		return false, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func Test_waitUntilTimesOut(t *testing.T) {
	start := time.Now()
	err := waitUntil(10*time.Millisecond, time.Millisecond, func() (bool, error) {
		return false, nil
	})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("bounded wait exceeded expected test duration")
	}
}
