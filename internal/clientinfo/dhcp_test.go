package clientinfo

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func Test_readClientInfoReader(t *testing.T) {
	d := &dhcp{}
	tests := []struct {
		name     string
		in       string
		readFunc func(r io.Reader) error
		mac      string
		hostname string
	}{
		{
			"good dnsmasq",
			`1683329857 e6:20:59:b8:c1:6d 192.168.1.186 host1 01:e6:20:59:b8:c1:6d
`,
			d.dnsmasqReadClientInfoReader,
			"e6:20:59:b8:c1:6d",
			"host1",
		},
		{
			"bad dnsmasq seen on UDMdream machine",
			`1683329857 e6:20:59:b8:c1:6e 192.168.1.111 host1 01:e6:20:59:b8:c1:6e
duid 00:01:00:01:2b:e4:2e:2c:52:52:14:26:dc:1c
1683322985 117442354 2600:4040:b0e6:b700::111 ASDASD 00:01:00:01:2a:d0:b9:81:00:07:32:4c:1c:07
`,
			d.dnsmasqReadClientInfoReader,
			"e6:20:59:b8:c1:6e",
			"host1",
		},
		{
			"isc-dhcpd good",
			`lease 192.168.1.1 {
    hardware ethernet 00:00:00:00:00:01;
    client-hostname "host-1";
}
`,
			d.iscDHCPReadClientInfoReader,
			"00:00:00:00:00:01",
			"host-1",
		},
		{
			"isc-dhcpd bad dhcp",
			`lease 192.168.1.1 {
    hardware ethernet invalid-dhcp;
    client-hostname "host-1";
}

lease 192.168.1.2 {
    hardware ethernet 00:00:00:00:00:02;
    client-hostname "host-2";
}
`,
			d.iscDHCPReadClientInfoReader,
			"00:00:00:00:00:02",
			"host-2",
		},
		{
			"",
			`1685794060 00:00:00:00:00:04 192.168.0.209 example 00:00:00:00:00:04 9`,
			d.dnsmasqReadClientInfoReader,
			"00:00:00:00:00:04",
			"example",
		},
		{
			"kea-dhcp4 good",
			`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.0.123,00:00:00:00:00:05,00:00:00:00:00:05,7200,1703290639,1,0,0,foo,0,,0
`,
			d.keaDhcp4ReadClientInfoReader,
			"00:00:00:00:00:05",
			"foo",
		},
		{
			"kea-dhcp4 no-header",
			`192.168.0.123,00:00:00:00:00:05,00:00:00:00:00:05,7200,1703290639,1,0,0,foo,0,,0`,
			d.keaDhcp4ReadClientInfoReader,
			"00:00:00:00:00:05",
			"foo",
		},
		{
			"kea-dhcp4 hostname *",
			`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.0.123,00:00:00:00:00:05,00:00:00:00:00:05,7200,1703290639,1,0,0,*,0,,0
`,
			d.keaDhcp4ReadClientInfoReader,
			"00:00:00:00:00:05",
			"*",
		},
		{
			"kea-dhcp4 bad",
			`address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.0.123,00:00:00:00:00:05,00:00:00:00:00:05,7200,1703290639,1,0,0,foo,0,,0
192.168.0.124,invalid_MAC,00:00:00:00:00:05,7200,1703290639,1,0,0,foo,0,,0
`,
			d.keaDhcp4ReadClientInfoReader,
			"00:00:00:00:00:05",
			"foo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d.mac2name.Delete(tc.mac)
			if err := tc.readFunc(strings.NewReader(tc.in)); err != nil {
				t.Errorf("readClientInfoReader() error = %v", err)
			}
			val, existed := d.mac2name.Load(tc.mac)
			if tc.hostname == "*" {
				if existed {
					t.Errorf("* hostname must be skipped")
				}
				return
			}
			if !existed {
				t.Error("client info missing")
			}
			hostname := val.(string)
			if existed && hostname != tc.hostname {
				t.Errorf("hostname mismatched, want: %q, got: %q", tc.hostname, hostname)
			}
		})
	}
}

func Test_dhcp_lookupIPByHostname(t *testing.T) {
	d := &dhcp{}
	want := "192.168.1.123"
	d.ip2name.Store(want, "foo")
	d.ip2name.Store("127.0.0.1", "foo")
	d.ip2name.Store("169.254.123.123", "foo")

	if got := d.lookupIPByHostname("foo", false); got != want {
		t.Fatalf("unexpected result, want: %s, got: %s", want, got)
	}
}


func TestDynamicDnsmasqLeaseFileFormat(t *testing.T) {
	tests := []struct {
		name string
		path string
		ok   bool
	}{
		{"merlin sdn", "/var/lib/misc/dnsmasq-1.leases", true},
		{"merlin later sdn", "/var/lib/misc/dnsmasq-123.leases", true},
		{"edgeos dnsmasq", "/run/dnsmasq-dhcp.leases", true},
		{"main dnsmasq", "/var/lib/misc/dnsmasq.leases", false},
		{"unrelated lease", "/var/lib/misc/other.leases", false},
		{"similar suffix", "/var/lib/misc/dnsmasq-1.leases.bak", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			format, ok := dynamicDnsmasqLeaseFileFormat(tc.path)
			if ok != tc.ok {
				t.Fatalf("dynamicDnsmasqLeaseFileFormat(%q) ok=%v, want %v", tc.path, ok, tc.ok)
			}
			if ok && format != "dnsmasq" {
				t.Fatalf("dynamic format = %q, want dnsmasq", format)
			}
		})
	}
}


func TestDiscoverDynamicLeaseFilesScansExistingFiles(t *testing.T) {
	dir := t.TempDir()
	lease := filepath.Join(dir, "dnsmasq-7.leases")
	if err := os.WriteFile(lease, []byte("1683329857 e6:20:59:b8:c1:6d 192.168.1.186 host1 *\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unrelated.leases"), []byte("ignored\n"), 0644); err != nil {
		t.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	d := &dhcp{watcher: watcher}
	if err := d.discoverDynamicLeaseFiles(dir); err != nil {
		t.Fatal(err)
	}

	format, ok := clientInfoFileFormat(lease)
	if !ok || format != "dnsmasq" {
		t.Fatalf("dynamic lease file was not registered: ok=%v format=%q", ok, format)
	}
	if got := d.LookupHostnameByMac("e6:20:59:b8:c1:6d"); got != "host1" {
		t.Fatalf("hostname = %q, want host1", got)
	}

	// Keep the package-global registry isolated from subsequent tests.
	clientInfoFilesMu.Lock()
	delete(clientInfoFiles, lease)
	clientInfoFilesMu.Unlock()
}

func TestDiscoverDynamicLeaseFilesIgnoresUnrelatedFiles(t *testing.T) {
	dir := t.TempDir()
	unrelated := filepath.Join(dir, "other.leases")
	if err := os.WriteFile(unrelated, []byte("ignored\n"), 0644); err != nil {
		t.Fatal(err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer watcher.Close()

	d := &dhcp{watcher: watcher}
	if err := d.discoverDynamicLeaseFiles(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok := clientInfoFileFormat(unrelated); ok {
		t.Fatalf("unrelated file was unexpectedly registered: %s", unrelated)
	}
}
