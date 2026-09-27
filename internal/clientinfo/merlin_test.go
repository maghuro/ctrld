package clientinfo

import (
	"testing"
)

func TestParseMerlinCustomClientList(t *testing.T) {
	tests := []struct {
		name              string
		clientList        string
		macList           []string
		hostnameList      []string
		macNotPresentList []string
	}{
		{
			"normal",
			"<client1>00:00:00:00:00:01>0>4>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			nil,
		},
		{
			"multiple clients",
			"<client1>00:00:00:00:00:01>0>4>><client2>00:00:00:00:00:02>0>24>>",
			[]string{"00:00:00:00:00:01", "00:00:00:00:00:02"},
			[]string{"client1", "client2"},
			nil,
		},
		{
			"empty hostname",
			"<client1>00:00:00:00:00:01>0>4>><>00:00:00:00:00:02>0>24>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			[]string{"00:00:00:00:00:02"},
		},
		{
			"empty dhcp",
			"<client1>00:00:00:00:00:01>0>4>><client 1>>>",
			[]string{"00:00:00:00:00:01"},
			[]string{"client1"},
			[]string{""},
		},
		{
			"invalid",
			"qwerty",
			nil,
			nil,
			nil,
		},
		{
			"empty",
			"",

			nil,
			nil,
			nil,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &merlinDiscover{}
			m.parseMerlinCustomClientList(tc.clientList)
			for i, mac := range tc.macList {
				hostname := m.LookupHostnameByMac(mac)
				if hostname != tc.hostnameList[i] {
					t.Errorf("hostname mismatch, want: %q, got: %q", tc.hostnameList[i], hostname)
				}
			}
			for _, mac := range tc.macNotPresentList {
				if hostname := m.LookupHostnameByMac(mac); hostname != "" {
					t.Errorf("mac2name address %q should not be present, got %q", mac, hostname)
				}
			}
		})
	}
}


func TestParseMerlinCustomClientListReplacesPreviousSnapshot(t *testing.T) {
	m := &merlinDiscover{}
	m.parseMerlinCustomClientList(
		"<old-client>00:00:00:00:00:01>0>4>><removed-client>00:00:00:00:00:02>0>24>>",
	)
	m.parseMerlinCustomClientList(
		"<renamed-client>00:00:00:00:00:01>0>4>><new-client>00:00:00:00:00:03>0>24>>",
	)

	if got := m.LookupHostnameByMac("00:00:00:00:00:01"); got != "renamed-client" {
		t.Fatalf("renamed client = %q, want %q", got, "renamed-client")
	}
	if got := m.LookupHostnameByMac("00:00:00:00:00:02"); got != "" {
		t.Fatalf("removed client remained cached as %q", got)
	}
	if got := m.LookupHostnameByMac("00:00:00:00:00:03"); got != "new-client" {
		t.Fatalf("new client = %q, want %q", got, "new-client")
	}
}

func TestParseMerlinCustomClientListEmptySnapshotClearsCache(t *testing.T) {
	m := &merlinDiscover{}
	m.parseMerlinCustomClientList("<client1>00:00:00:00:00:01>0>4>>")
	m.parseMerlinCustomClientList("")

	if got := m.LookupHostnameByMac("00:00:00:00:00:01"); got != "" {
		t.Fatalf("empty snapshot left stale hostname %q", got)
	}
}


func TestParseMerlinCustomClientListPublishesNewImmutableMap(t *testing.T) {
	m := &merlinDiscover{}
	m.parseMerlinCustomClientList("<old>00:00:00:00:00:01>0>4>>")
	oldSnapshot := m.hostname.Load()
	if oldSnapshot == nil {
		t.Fatal("missing first published snapshot")
	}

	m.parseMerlinCustomClientList("<new>00:00:00:00:00:02>0>4>>")
	newSnapshot := m.hostname.Load()
	if newSnapshot == nil {
		t.Fatal("missing second published snapshot")
	}
	if oldSnapshot == newSnapshot {
		t.Fatal("refresh mutated/reused the published map instead of atomically swapping a new snapshot")
	}
	if got := (*oldSnapshot)["00:00:00:00:00:01"]; got != "old" {
		t.Fatalf("previous immutable snapshot changed after refresh: %q", got)
	}
	if _, ok := (*newSnapshot)["00:00:00:00:00:01"]; ok {
		t.Fatal("new snapshot retained a removed client")
	}
}
