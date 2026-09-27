package clientinfo

import (
	"strings"
	"sync/atomic"

	"github.com/Control-D-Inc/ctrld/internal/router"
	"github.com/Control-D-Inc/ctrld/internal/router/merlin"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const merlinNvramCustomClientListKey = "custom_clientlist"

type merlinDiscover struct {
	// Each published map is immutable. Refresh builds a complete replacement
	// off to the side and swaps the pointer once, so concurrent lookups never
	// observe an empty/partial/interleaved custom_clientlist snapshot.
	hostname atomic.Pointer[map[string]string]
}

func (m *merlinDiscover) refresh() error {
	if router.Name() != merlin.Name {
		return nil
	}
	out, err := nvram.Run("get", merlinNvramCustomClientListKey)
	if err != nil {
		return err
	}
	ctrld.ProxyLogger.Load().Debug().Msg("reading Merlin custom client list")
	m.parseMerlinCustomClientList(out)
	return nil
}

func (m *merlinDiscover) LookupHostnameByIP(ip string) string {
	return ""
}

func (m *merlinDiscover) LookupHostnameByMac(mac string) string {
	snapshot := m.hostname.Load()
	if snapshot == nil {
		return ""
	}
	return (*snapshot)[mac]
}

// "nvram get custom_clientlist" output:
//
// <client 1>00:00:00:00:00:01>0>4>><client 2>00:00:00:00:00:02>0>24>>...
//
// So to parse it, do the following steps:
//
//   - Split by "<"                 => entries
//   - For each entry, split by ">" => parts
//   - Empty parts                  => skip
//   - Empty parts[0]               => skip empty hostname
//   - Empty parts[1]               => skip empty MAC
func (m *merlinDiscover) parseMerlinCustomClientList(data string) {
	// custom_clientlist is a complete snapshot, not a delta. Build the next
	// immutable snapshot privately and publish it with one atomic pointer swap.
	next := make(map[string]string)
	entries := strings.Split(data, "<")
	for _, entry := range entries {
		parts := strings.SplitN(string(entry), ">", 3)
		if len(parts) < 2 || len(parts[0]) == 0 || len(parts[1]) == 0 {
			continue
		}
		hostname := normalizeHostname(parts[0])
		mac := strings.ToLower(parts[1])
		next[mac] = hostname
	}
	m.hostname.Store(&next)
}

func (m *merlinDiscover) String() string {
	return "merlin"
}
