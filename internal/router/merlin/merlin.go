package merlin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const Name = "merlin"

const (
	merlinManagedStatePath = "/jffs/controld/.merlin-dnsmasq-hooks-v2"
	merlinSnapshotStatePath = "/jffs/controld/.merlin-dnsmasq-snapshot"
	merlinCleanupPendingPath = "/jffs/controld/.merlin-dnsmasq-cleanup-pending"
)

// nvramKvMap is a map of NVRAM key-value pairs used to configure and manage Merlin-specific settings.
var nvramKvMap = map[string]string{
	"dnspriv_enable": "0", // Ensure Merlin native DoT disabled.
}

// dnsmasqConfig represents configuration paths for dnsmasq operations in Merlin firmware.
type dnsmasqConfig struct {
	confPath     string
	jffsConfPath string
}

// Merlin represents a configuration handler for setting up and managing ctrld on Merlin routers.
type Merlin struct {
	cfg *ctrld.Config
}

// New returns a router.Router for configuring/setup/run ctrld on Merlin routers.
func New(cfg *ctrld.Config) *Merlin {
	return &Merlin{cfg: cfg}
}

// ConfigureService configures the service based on the provided configuration. It returns an error if the configuration fails.
func (m *Merlin) ConfigureService(config *service.Config) error {
	return nil
}

// Install sets up the necessary configurations and services required for the Merlin instance to function properly.
func (m *Merlin) Install(_ *service.Config) error {
	return nil
}

// Uninstall removes the ctrld-related configurations and services from the Merlin router and reverts to the original state.
func (m *Merlin) Uninstall(_ *service.Config) error {
	return nil
}

// PreRun prepares the Merlin instance for operation by waiting for essential services and directories to become available.
func (m *Merlin) PreRun() error {
	// Reconcile any previous Merlin integration before starting again. Router
	// startup is a one-shot launch, so retry transient JFFS/NVRAM/dnsmasq errors
	// here instead of abandoning DNS in a partially reconciled state.
	var cleanupErr error
	for attempt := 1; attempt <= 3; attempt++ {
		cleanupErr = m.Cleanup()
		if cleanupErr == nil {
			break
		}
		if attempt < 3 {
			time.Sleep(time.Second)
		}
	}
	if cleanupErr != nil {
		return fmt.Errorf("failed to cleanup previous Merlin integration after retries: %w", cleanupErr)
	}
	// Wait NTP ready.
	if err := ntp.WaitNvram(); err != nil {
		return err
	}
	// Wait until directories mounted.
	for _, dir := range []string{"/tmp", "/proc"} {
		waitDirExists(dir)
	}
	// Wait dnsmasq started.
	for {
		out, _ := exec.Command("pidof", "dnsmasq").CombinedOutput()
		if len(bytes.TrimSpace(out)) > 0 {
			break
		}
		time.Sleep(time.Second)
	}
	return nil
}

// Setup initializes and configures the Merlin instance for use, including setting up dnsmasq and necessary nvram settings.
func (m *Merlin) Setup() (retErr error) {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Already setup.
	setupVal, err := nvram.Run("get", nvram.CtrldSetupKey)
	if err != nil {
		return fmt.Errorf("read Merlin setup state: %w", err)
	}
	if setupVal == "1" {
		return nil
	}

	// Mark this as the hook-based integration before changing NVRAM so any
	// failure after this point is rollback-visible.
	if err := atomicWriteFile(merlinManagedStatePath, []byte("hooks-v2\n"), 0600); err != nil {
		return fmt.Errorf("failed to write Merlin integration state: %w", err)
	}

	defer func() {
		if retErr == nil {
			return
		}
		if cleanupErr := m.Cleanup(); cleanupErr != nil {
			retErr = fmt.Errorf("%v; rollback failed: %w", retErr, cleanupErr)
		}
	}()

	// Apply NVRAM changes before regenerating dnsmasq so the firmware-generated
	// config reflects ctrld's desired DNS Privacy state. nvram.SetKV rolls back
	// its own partial mutations on failure.
	if err := nvram.SetKV(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	if err := m.writeDnsmasqPostconf(); err != nil {
		return err
	}

	// On Merlin 3006 this restarts the main and all SDN dnsmasq instances,
	// causing dnsmasq.postconf and dnsmasq-sdn.postconf to run.
	if err := restartDNSMasq(); err != nil {
		return err
	}

	mainOK, err := m.dnsmasqConfigUsesCtrld(dnsmasq.MerlinConfPath)
	if err != nil {
		return err
	}
	if !mainOK {
		// Compatibility fallback for older Merlin devices where postconf is
		// known not to execute. Never overwrite an unowned user config.
		if err := m.setupMainDnsmasqFallback(); err != nil {
			return err
		}
		if err := restartDNSMasq(); err != nil {
			return err
		}
		mainOK, err = m.dnsmasqConfigUsesCtrld(dnsmasq.MerlinConfPath)
		if err != nil {
			return err
		}
		if !mainOK {
			return fmt.Errorf("Merlin dnsmasq integration was not applied to %s", dnsmasq.MerlinConfPath)
		}
	}

	// Additional dnsmasq instances are Guest Network Pro / SDN instances on
	// Merlin 3006. Their supported extension point is dnsmasq-sdn.postconf;
	// full /jffs/configs/dnsmasq-N.conf files are not consumed by Merlin.
	for _, path := range dnsmasq.AdditionalConfigFiles() {
		ok, err := m.dnsmasqConfigUsesCtrld(path)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("Merlin SDN dnsmasq integration was not applied to %s", path)
		}
	}

	return nil
}

type legacySnapshotEntry struct {
	path string
	hash string
}

type legacyCleanupJournal struct {
	phase   string
	entries []legacySnapshotEntry
}

// Cleanup restores the original dnsmasq and nvram configurations and restarts dnsmasq if necessary.
func (m *Merlin) Cleanup() error {
	// Preserve the existing direct-listener lifecycle. A direct listener needs
	// port 53 itself; restarting dnsmasq here would reclaim that port before
	// ctrld binds. Transitioning between forwarding and direct-listener modes
	// requires a separate port-ownership design and is outside this change.
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}

	setupVal, err := nvram.Run("get", nvram.CtrldSetupKey)
	if err != nil {
		return fmt.Errorf("read Merlin setup state during cleanup: %w", err)
	}
	managed, err := pathExists(merlinManagedStatePath)
	if err != nil {
		return fmt.Errorf("stat Merlin managed state: %w", err)
	}

	journal, err := readLegacyCleanupJournal()
	if err != nil {
		return fmt.Errorf("read Merlin legacy cleanup state: %w", err)
	}
	if setupVal != "1" && !managed && journal.phase == "" {
		return nil
	}

	legacy := journal.phase != "" || (setupVal == "1" && !managed)
	if legacy && journal.phase == "" {
		journal, err = buildLegacyCleanupJournal()
		if err != nil {
			return err
		}
		if err := writeLegacyCleanupJournal(journal); err != nil {
			return fmt.Errorf("journal legacy dnsmasq snapshots: %w", err)
		}
	}

	for _, path := range []string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath} {
		if err := cleanupDnsmasqPostconf(path); err != nil {
			return err
		}
	}

	if legacy {
		switch journal.phase {
		case "cleanup-v1":
			// The exact snapshot paths and hashes were durably recorded before
			// the first destructive operation. Retries consult only this journal,
			// never a fresh directory enumeration, so a user-created replacement
			// cannot be mistaken for ctrld's old snapshot.
			for _, entry := range journal.entries {
				buf, err := os.ReadFile(entry.path)
				switch {
				case err == nil:
					if merlinSnapshotHash(buf) != entry.hash {
						continue
					}
					if err := os.Remove(entry.path); err != nil && !os.IsNotExist(err) {
						return fmt.Errorf("remove journaled legacy snapshot %s: %w", entry.path, err)
					}
				case os.IsNotExist(err):
					// Already removed on a previous attempt.
				default:
					return fmt.Errorf("read journaled legacy snapshot %s: %w", entry.path, err)
				}
			}
			if err := syncParentDir(dnsmasq.MerlinJffsConfDir); err != nil {
				return fmt.Errorf("sync legacy snapshot directory: %w", err)
			}
			journal.phase = "finalize"
			journal.entries = nil
			if err := writeLegacyCleanupJournal(journal); err != nil {
				return fmt.Errorf("advance Merlin legacy cleanup state: %w", err)
			}
		case "finalize":
			// Destructive legacy cleanup already completed. A retry must never
			// reinterpret newly created user files as legacy ctrld snapshots.
		default:
			return fmt.Errorf("unknown Merlin legacy cleanup phase %q", journal.phase)
		}
	} else {
		if err := cleanupOwnedMainSnapshot(); err != nil {
			return err
		}
	}

	// Restore NVRAM only after ctrld-owned artifacts are cleaned successfully.
	if setupVal == "1" {
		if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
			return err
		}
	}

	if err := restartDNSMasq(); err != nil {
		return err
	}

	if err := removeFileDurable(merlinManagedStatePath); err != nil {
		return fmt.Errorf("remove Merlin managed state: %w", err)
	}
	if journal.phase != "" {
		if err := removeFileDurable(merlinCleanupPendingPath); err != nil {
			return fmt.Errorf("remove Merlin legacy cleanup state: %w", err)
		}
	}
	return nil
}

func buildLegacyCleanupJournal() (legacyCleanupJournal, error) {
	paths := []string{dnsmasq.MerlinJffsConfPath}
	matches, err := filepath.Glob(filepath.Join(dnsmasq.MerlinJffsConfDir, "dnsmasq-*.conf"))
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	paths = append(paths, matches...)

	journal := legacyCleanupJournal{phase: "cleanup-v1"}
	for _, path := range paths {
		if !isLegacySnapshotPath(path) {
			continue
		}
		buf, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("read legacy dnsmasq snapshot %s: %w", path, err)
		}
		journal.entries = append(journal.entries, legacySnapshotEntry{
			path: path,
			hash: merlinSnapshotHash(buf),
		})
	}
	return journal, nil
}

func writeLegacyCleanupJournal(journal legacyCleanupJournal) error {
	buf, err := encodeLegacyCleanupJournal(journal)
	if err != nil {
		return err
	}
	return atomicWriteFile(merlinCleanupPendingPath, buf, 0600)
}

func encodeLegacyCleanupJournal(journal legacyCleanupJournal) ([]byte, error) {
	var b strings.Builder
	b.WriteString(journal.phase)
	b.WriteByte('\n')
	for _, entry := range journal.entries {
		if !isLegacySnapshotPath(entry.path) {
			return nil, fmt.Errorf("invalid legacy snapshot path %q", entry.path)
		}
		if _, err := hex.DecodeString(entry.hash); err != nil || len(entry.hash) != sha256.Size*2 {
			return nil, fmt.Errorf("invalid legacy snapshot hash for %s", entry.path)
		}
		b.WriteString(entry.path)
		b.WriteByte('\t')
		b.WriteString(entry.hash)
		b.WriteByte('\n')
	}
	return []byte(b.String()), nil
}

func readLegacyCleanupJournal() (legacyCleanupJournal, error) {
	buf, err := os.ReadFile(merlinCleanupPendingPath)
	if os.IsNotExist(err) {
		return legacyCleanupJournal{}, nil
	}
	if err != nil {
		return legacyCleanupJournal{}, err
	}
	return parseLegacyCleanupJournal(buf)
}

func parseLegacyCleanupJournal(buf []byte) (legacyCleanupJournal, error) {
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return legacyCleanupJournal{}, fmt.Errorf("empty legacy cleanup journal")
	}
	journal := legacyCleanupJournal{phase: lines[0]}
	if journal.phase == "finalize" {
		if len(lines) != 1 {
			return legacyCleanupJournal{}, fmt.Errorf("finalize journal contains snapshot entries")
		}
		return journal, nil
	}
	if journal.phase != "cleanup-v1" {
		return legacyCleanupJournal{}, fmt.Errorf("unknown legacy cleanup phase %q", journal.phase)
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 || !isLegacySnapshotPath(parts[0]) {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy cleanup journal entry %q", line)
		}
		if len(parts[1]) != sha256.Size*2 {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy snapshot hash for %s", parts[0])
		}
		if _, err := hex.DecodeString(parts[1]); err != nil {
			return legacyCleanupJournal{}, fmt.Errorf("invalid legacy snapshot hash for %s: %w", parts[0], err)
		}
		journal.entries = append(journal.entries, legacySnapshotEntry{path: parts[0], hash: parts[1]})
	}
	return journal, nil
}

func isLegacySnapshotPath(path string) bool {
	if path == dnsmasq.MerlinJffsConfPath {
		return true
	}
	if filepath.Dir(path) != dnsmasq.MerlinJffsConfDir {
		return false
	}
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "dnsmasq-") || !strings.HasSuffix(base, ".conf") {
		return false
	}
	middle := strings.TrimSuffix(strings.TrimPrefix(base, "dnsmasq-"), ".conf")
	if middle == "" {
		return false
	}
	for _, r := range middle {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func readMerlinState(path string) (string, error) {
	buf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf)), nil
}

// dnsmasqConfigUsesCtrld reports whether a generated dnsmasq config has the
// complete ctrld forwarding shape, not merely one matching server line.
func (m *Merlin) dnsmasqConfigUsesCtrld(path string) (bool, error) {
	buf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	listener := m.cfg.FirstListener()
	if listener == nil {
		return false, fmt.Errorf("missing ctrld listener")
	}
	ip := listener.IP
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		ip = "127.0.0.1"
	}
	expectedServer := fmt.Sprintf("server=%s#%d", ip, listener.Port)

	var (
		serverCount int
		expectedSeen bool
		noResolv     bool
		addMAC       bool
		addSubnet    bool
		cacheOff     bool
	)
	for _, raw := range strings.Split(string(buf), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "server="):
			serverCount++
			if line == expectedServer {
				expectedSeen = true
			}
		case strings.HasPrefix(line, "servers-file="),
			strings.HasPrefix(line, "resolv-file="),
			line == "dnssec",
			strings.HasPrefix(line, "trust-anchor="):
			return false, nil
		case line == "no-resolv":
			noResolv = true
		case line == "add-mac":
			addMAC = true
		case line == "add-subnet=32,128":
			addSubnet = true
		case line == "cache-size=0":
			cacheOff = true
		}
	}

	return serverCount == 1 && expectedSeen && noResolv && addMAC && addSubnet && cacheOff, nil
}

// setupMainDnsmasqFallback retains the old full-config mechanism only for the
// main dnsmasq when the supported postconf hook demonstrably did not apply.
// Ownership is published before the final snapshot, and content hashes prevent
// ctrld from later deleting or overwriting a user-modified file.
func (m *Merlin) setupMainDnsmasqFallback() error {
	owned, err := mainSnapshotOwnership()
	if err != nil {
		return err
	}
	snapshotExists, err := pathExists(dnsmasq.MerlinJffsConfPath)
	if err != nil {
		return fmt.Errorf("stat Merlin fallback config: %w", err)
	}
	if snapshotExists {
		if !owned {
			return fmt.Errorf("refusing to overwrite unowned or modified Merlin custom config: %s", dnsmasq.MerlinJffsConfPath)
		}
		if err := cleanupOwnedMainSnapshot(); err != nil {
			return err
		}
	} else {
		stateExists, err := pathExists(merlinSnapshotStatePath)
		if err != nil {
			return fmt.Errorf("stat Merlin fallback ownership: %w", err)
		}
		if stateExists {
			// A previous crash may have published ownership before the snapshot.
			if err := removeFileDurable(merlinSnapshotStatePath); err != nil {
				return fmt.Errorf("remove orphaned Merlin snapshot state: %w", err)
			}
		}
	}

	buf, err := os.ReadFile(dnsmasq.MerlinConfPath)
	if err != nil {
		return fmt.Errorf("failed to read dnsmasq config for fallback: %w", err)
	}
	built, err := m.buildMainDnsmasqFallback(buf)
	if err != nil {
		return err
	}
	hash := merlinSnapshotHash(built)

	// Publish durable ownership first. If the router stops before the snapshot
	// rename, cleanup sees a harmless orphaned marker and removes it.
	if err := atomicWriteFile(merlinSnapshotStatePath, []byte("sha256="+hash+"\n"), 0600); err != nil {
		return fmt.Errorf("mark ctrld dnsmasq fallback ownership: %w", err)
	}
	if err := atomicWriteFile(dnsmasq.MerlinJffsConfPath, built, 0644); err != nil {
		current, readErr := os.ReadFile(dnsmasq.MerlinJffsConfPath)
		switch {
		case readErr == nil && merlinSnapshotHash(current) == hash:
			// Rename reached the target. Keep the already-durable ownership marker
			// so deferred/retry cleanup can safely remove the visible fallback.
			return fmt.Errorf("publish ctrld dnsmasq fallback after rename: %w", err)
		case os.IsNotExist(readErr):
			if removeErr := removeFileDurable(merlinSnapshotStatePath); removeErr != nil {
				return fmt.Errorf("publish ctrld dnsmasq fallback: %w; remove ownership state: %v", err, removeErr)
			}
			return fmt.Errorf("publish ctrld dnsmasq fallback: %w", err)
		case readErr == nil:
			// A different readable file is present, so ctrld cannot claim it.
			if removeErr := removeFileDurable(merlinSnapshotStatePath); removeErr != nil {
				return fmt.Errorf("publish ctrld dnsmasq fallback: %w; unexpected target and ownership cleanup failed: %v", err, removeErr)
			}
			return fmt.Errorf("publish ctrld dnsmasq fallback: %w; target content does not match ctrld snapshot", err)
		default:
			// Publication state is uncertain. Retain the marker rather than turn
			// a possibly successful rename into a permanently unowned snapshot.
			return fmt.Errorf("publish ctrld dnsmasq fallback: %w; verify target: %v", err, readErr)
		}
	}
	return nil
}

func (m *Merlin) buildMainDnsmasqFallback(buf []byte) ([]byte, error) {
	tmp, err := os.CreateTemp(dnsmasq.MerlinJffsConfDir, ".dnsmasq.conf.ctrld-build-*")
	if err != nil {
		return nil, fmt.Errorf("create ctrld dnsmasq fallback build file: %w", err)
	}
	path := tmp.Name()
	defer os.Remove(path)

	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if _, err := tmp.Write(buf); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}

	script, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return nil, fmt.Errorf("render ctrld fallback postconf: %w", err)
	}
	// Apply only ctrld's managed logic. Executing the shared Merlin hook here
	// would also execute unrelated addon/user blocks a second time against a
	// temporary file.
	cmd := exec.Command("/bin/sh", "-c", script, "ctrld-fallback", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to apply ctrld fallback postconf: %s: %w", string(out), err)
	}
	built, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ctrld dnsmasq fallback build: %w", err)
	}
	return built, nil
}

func merlinSnapshotHash(buf []byte) string {
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:])
}

func readMainSnapshotHash() (string, bool, error) {
	state, err := readMerlinState(merlinSnapshotStatePath)
	if err != nil {
		return "", false, err
	}
	if state == "" {
		return "", false, nil
	}
	const prefix = "sha256="
	if !strings.HasPrefix(state, prefix) || len(state) != len(prefix)+sha256.Size*2 {
		return "", false, fmt.Errorf("invalid Merlin dnsmasq snapshot ownership state")
	}
	hash := strings.TrimPrefix(state, prefix)
	if _, err := hex.DecodeString(hash); err != nil {
		return "", false, fmt.Errorf("invalid Merlin dnsmasq snapshot hash: %w", err)
	}
	return hash, true, nil
}

func mainSnapshotOwnership() (bool, error) {
	expected, marked, err := readMainSnapshotHash()
	if err != nil || !marked {
		return false, err
	}
	buf, err := os.ReadFile(dnsmasq.MerlinJffsConfPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return merlinSnapshotHash(buf) == expected, nil
}

func cleanupOwnedMainSnapshot() error {
	expected, marked, err := readMainSnapshotHash()
	if err != nil {
		return err
	}
	if !marked {
		return nil
	}

	buf, err := os.ReadFile(dnsmasq.MerlinJffsConfPath)
	if os.IsNotExist(err) {
		return removeFileDurable(merlinSnapshotStatePath)
	}
	if err != nil {
		return err
	}
	if merlinSnapshotHash(buf) != expected {
		return fmt.Errorf("refusing to remove modified Merlin dnsmasq fallback: %s", dnsmasq.MerlinJffsConfPath)
	}
	if err := removeFileDurable(dnsmasq.MerlinJffsConfPath); err != nil {
		return err
	}
	if err := removeFileDurable(merlinSnapshotStatePath); err != nil {
		return err
	}
	return nil
}

// cleanupDnsmasqJffs removes the JFFS configuration file specified in the given dnsmasqConfig, if it exists.
func (m *Merlin) cleanupDnsmasqJffs(cfg *dnsmasqConfig) error {
	// Remove cfg.jffsConfPath file.
	if err := os.Remove(cfg.jffsConfPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// merlinHookUpdate is prepared entirely before any shared hook is modified.
// This lets us validate/read both Merlin hook paths before the first write.
type merlinHookUpdate struct {
	path          string
	data          []byte
	original      []byte
	existed       bool
	pathType      os.FileMode
	symlinkTarget string
}

// writeDnsmasqPostconf installs ctrld-owned blocks in Merlin's main and SDN
// hooks while preserving unrelated content. Both paths are preflighted before
// either is modified, avoiding a half-installed integration when the second
// shared hook is unreadable or otherwise invalid.
func (m *Merlin) writeDnsmasqPostconf() error {
	data, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return err
	}
	block := []byte(strings.Join([]string{
		dnsmasq.MerlinPostConfBeginMarker,
		strings.TrimSpace(data),
		dnsmasq.MerlinPostConfEndMarker,
	}, "\n"))

	return writeMerlinHookUpdates(
		[]string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath},
		block,
	)
}

func writeMerlinHookUpdates(paths []string, block []byte) error {
	return writeMerlinHookUpdatesWith(paths, block, atomicWriteFile)
}

func writeMerlinHookUpdatesWith(
	paths []string,
	block []byte,
	writeFile func(string, []byte, os.FileMode) error,
) error {
	updates := make([]merlinHookUpdate, 0, len(paths))
	for _, path := range paths {
		update, err := prepareMerlinHookUpdate(path, block)
		if err != nil {
			return err
		}
		updates = append(updates, update)
	}

	written := make([]merlinHookUpdate, 0, len(updates))
	for _, update := range updates {
		if err := revalidateMerlinHookUpdate(update); err != nil {
			if rollbackErr := rollbackMerlinHookUpdates(written); rollbackErr != nil {
				return fmt.Errorf("revalidate Merlin hook %s: %w; rollback failed: %v", update.path, err, rollbackErr)
			}
			return fmt.Errorf("revalidate Merlin hook %s: %w", update.path, err)
		}
		if err := writeFile(update.path, update.data, 0750); err != nil {
			if rollbackErr := rollbackMerlinHookUpdates(written); rollbackErr != nil {
				return fmt.Errorf("write Merlin hook %s: %w; rollback failed: %v", update.path, err, rollbackErr)
			}
			return fmt.Errorf("write Merlin hook %s: %w", update.path, err)
		}
		written = append(written, update)
	}
	return nil
}

func rollbackMerlinHookUpdates(updates []merlinHookUpdate) error {
	for i := len(updates) - 1; i >= 0; i-- {
		update := updates[i]
		current, err := os.ReadFile(update.path)
		if err != nil {
			return fmt.Errorf("read %s during rollback: %w", update.path, err)
		}
		if !bytes.Equal(current, update.data) {
			return fmt.Errorf("refusing to roll back %s after external modification", update.path)
		}
		if update.existed {
			if err := atomicWriteFile(update.path, update.original, 0750); err != nil {
				return fmt.Errorf("restore %s: %w", update.path, err)
			}
			continue
		}
		if err := os.Remove(update.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove newly created %s: %w", update.path, err)
		}
	}
	return nil
}

func prepareMerlinHookUpdate(path string, block []byte) (merlinHookUpdate, error) {
	info, statErr := os.Lstat(path)
	pathMissing := os.IsNotExist(statErr)
	if statErr != nil && !pathMissing {
		return merlinHookUpdate{}, statErr
	}

	buf, err := os.ReadFile(path)
	if err != nil {
		if !pathMissing || !os.IsNotExist(err) {
			return merlinHookUpdate{}, err
		}
		buf = nil
	}

	update := merlinHookUpdate{
		path:     path,
		data:     merlinUpsertPostConf(buf, block),
		original: append([]byte(nil), buf...),
		existed:  !pathMissing,
	}
	if !pathMissing {
		update.pathType = info.Mode().Type()
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return merlinHookUpdate{}, err
			}
			update.symlinkTarget = target
		}
	}
	return update, nil
}

func revalidateMerlinHookUpdate(update merlinHookUpdate) error {
	info, err := os.Lstat(update.path)
	if !update.existed {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("shared hook appeared after preflight")
	}
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("shared hook disappeared after preflight")
		}
		return err
	}
	if info.Mode().Type() != update.pathType {
		return fmt.Errorf("shared hook type changed after preflight")
	}
	if update.pathType&os.ModeSymlink != 0 {
		target, err := os.Readlink(update.path)
		if err != nil {
			return err
		}
		if target != update.symlinkTarget {
			return fmt.Errorf("shared hook symlink target changed after preflight")
		}
	}
	current, err := os.ReadFile(update.path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, update.original) {
		return fmt.Errorf("shared hook content changed after preflight")
	}
	return nil
}

func cleanupDnsmasqPostconf(path string) error {
	buf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	clean := merlinParsePostConf(buf)
	// Never delete a shared Merlin hook outright. We cannot safely prove
	// persistent ownership across addon rewrites/reboots, so cleanup removes
	// only ctrld-owned bytes and leaves any resulting stub in place.
	return atomicWriteFile(path, clean, 0750)
}

// restartDNSMasq restarts the dnsmasq service by executing the appropriate system command using "service".
// Returns an error if the command fails or if there is an issue processing the command output.
func restartDNSMasq() error {
	if out, err := exec.Command("service", "restart_dnsmasq").CombinedOutput(); err != nil {
		return fmt.Errorf("restart_dnsmasq: %s, %w", string(out), err)
	}
	return nil
}

// getDnsmasqConfigs retrieves a list of dnsmasqConfig containing configuration and JFFS paths for dnsmasq operations.
func getDnsmasqConfigs() []*dnsmasqConfig {
	cfgs := []*dnsmasqConfig{
		{dnsmasq.MerlinConfPath, dnsmasq.MerlinJffsConfPath},
	}
	for _, path := range dnsmasq.AdditionalConfigFiles() {
		jffsConfPath := filepath.Join(dnsmasq.MerlinJffsConfDir, filepath.Base(path))
		cfgs = append(cfgs, &dnsmasqConfig{path, jffsConfPath})
	}

	return cfgs
}

// merlinExactLineBounds finds marker only when it occupies a complete line.
// The returned end excludes the line ending so callers can decide whether to
// preserve or consume that separator.
func merlinExactLineBounds(buf, marker []byte, from int) (start, end int, ok bool) {
	if from < 0 {
		from = 0
	}
	for pos := from; pos <= len(buf); {
		lineStart := pos
		relNL := bytes.IndexByte(buf[pos:], '\n')
		lineEnd := len(buf)
		next := len(buf) + 1
		if relNL >= 0 {
			lineEnd = pos + relNL
			next = lineEnd + 1
		}

		contentEnd := lineEnd
		if contentEnd > lineStart && buf[contentEnd-1] == '\r' {
			contentEnd--
		}
		if bytes.Equal(buf[lineStart:contentEnd], marker) {
			return lineStart, lineEnd, true
		}

		if relNL < 0 {
			break
		}
		pos = next
	}
	return 0, 0, false
}

// merlinLastExactLineBefore returns the last complete marker line starting
// before limit.
func merlinLastExactLineBefore(buf, marker []byte, limit int) (start, end int, ok bool) {
	from := 0
	for {
		s, e, found := merlinExactLineBounds(buf, marker, from)
		if !found || s >= limit {
			break
		}
		start, end, ok = s, e, true
		if e >= len(buf) {
			break
		}
		from = e + 1
	}
	return start, end, ok
}

type merlinPostConfBlockKind uint8

const (
	merlinPostConfBlockNone merlinPostConfBlockKind = iota
	merlinPostConfBlockCurrent
	merlinPostConfBlockLegacy
)

// merlinPostConfBlock returns the ctrld-owned block bounds and format.
// It understands both the current BEGIN/END format and the legacy <= 1.5.7
// GENERATED/EOF format. Markers must occupy complete lines so shell variables,
// comments or unrelated strings containing the marker text are never claimed.
func merlinPostConfBlock(buf []byte) (start, end int, kind merlinPostConfBlockKind, ok bool) {
	begin := []byte(dnsmasq.MerlinPostConfBeginMarker)
	endMarker := []byte(dnsmasq.MerlinPostConfEndMarker)
	if blockStart, beginEnd, found := merlinExactLineBounds(buf, begin, 0); found {
		from := beginEnd
		if from < len(buf) && buf[from] == '\n' {
			from++
		}
		if _, blockEnd, foundEnd := merlinExactLineBounds(buf, endMarker, from); foundEnd {
			return blockStart, blockEnd, merlinPostConfBlockCurrent, true
		}
	}

	legacyEnd := []byte(dnsmasq.MerlinPostConfMarker)
	if legacyEndStart, legacyEndEnd, found := merlinExactLineBounds(buf, legacyEnd, 0); found {
		legacyBegin := []byte(dnsmasq.CtrldMarker)
		if legacyBeginStart, _, foundBegin := merlinLastExactLineBefore(buf, legacyBegin, legacyEndStart); foundBegin {
			return legacyBeginStart, legacyEndEnd, merlinPostConfBlockLegacy, true
		}
	}

	return 0, 0, merlinPostConfBlockNone, false
}

func merlinConsumeLineEnding(buf []byte, pos int) int {
	if pos >= len(buf) {
		return pos
	}
	if buf[pos] == '\r' {
		pos++
		if pos < len(buf) && buf[pos] == '\n' {
			pos++
		}
		return pos
	}
	if buf[pos] == '\n' {
		return pos + 1
	}
	return pos
}

func merlinBlockHasSyntheticShebang(buf []byte, start, end int) bool {
	if start < 0 || end < start || end > len(buf) {
		return false
	}
	_, _, ok := merlinExactLineBounds(
		buf[start:end],
		[]byte(dnsmasq.MerlinSyntheticShebangMarker),
		0,
	)
	return ok
}

func merlinBlockWithSyntheticShebang(block []byte) []byte {
	prefix := []byte(dnsmasq.MerlinPostConfBeginMarker + "\n")
	if !bytes.HasPrefix(block, prefix) {
		return block
	}
	out := make([]byte, 0, len(block)+len(dnsmasq.MerlinSyntheticShebangMarker)+1)
	out = append(out, prefix...)
	out = append(out, dnsmasq.MerlinSyntheticShebangMarker...)
	out = append(out, '\n')
	out = append(out, block[len(prefix):]...)
	return out
}

// merlinParsePostConf removes only ctrld-owned postconf content while preserving
// unrelated hook logic before and after it. If ctrld had to synthesize the
// leading shebang for a pre-existing hook without one, that shebang is marked
// inside ctrld's block and removed together with the block.
func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	start, end, kind, ok := merlinPostConfBlock(buf)
	if !ok {
		return buf
	}

	syntheticShebang := kind == merlinPostConfBlockCurrent &&
		merlinBlockHasSyntheticShebang(buf, start, end)

	// Current blocks own the line ending following END. ctrld <= 1.5.7 wrote
	// its legacy wrapper with strings.Join(..., "\n"), producing three line
	// endings between the EOF marker and the previously existing hook.
	separatorCount := 1
	if kind == merlinPostConfBlockLegacy {
		separatorCount = 3
	}
	after := end
	for i := 0; i < separatorCount; i++ {
		next := merlinConsumeLineEnding(buf, after)
		if next == after {
			break
		}
		after = next
	}

	if syntheticShebang {
		const shebang = "#!/bin/sh\n"
		if start == len(shebang) && bytes.Equal(buf[:start], []byte(shebang)) {
			start = 0
		}
	}

	out := make([]byte, 0, len(buf)-(after-start))
	out = append(out, buf[:start]...)
	out = append(out, buf[after:]...)
	return out
}

// merlinUpsertPostConf replaces an existing ctrld block in place. New hooks,
// and existing hooks that do not already start with a usable shebang, receive a
// ctrld-owned synthetic shebang. The ownership marker lives inside the managed
// block so cleanup can remove that wrapper and restore the original bytes.
func merlinUpsertPostConf(buf, block []byte) []byte {
	if start, end, kind, ok := merlinPostConfBlock(buf); ok {
		if kind == merlinPostConfBlockCurrent {
			if merlinBlockHasSyntheticShebang(buf, start, end) {
				block = merlinBlockWithSyntheticShebang(block)
			}
			out := make([]byte, 0, len(buf)-(end-start)+len(block))
			out = append(out, buf[:start]...)
			out = append(out, block...)
			out = append(out, buf[end:]...)
			return out
		}

		// Legacy ctrld <= 1.5.7 wrote three separators after its EOF marker.
		after := end
		for i := 0; i < 3; i++ {
			next := merlinConsumeLineEnding(buf, after)
			if next == after {
				break
			}
			after = next
		}

		if start == 0 {
			marked := merlinBlockWithSyntheticShebang(block)
			out := make([]byte, 0, len(marked)+len(buf[after:])+16)
			out = append(out, "#!/bin/sh\n"...)
			out = append(out, marked...)
			out = append(out, '\n')
			out = append(out, buf[after:]...)
			return out
		}

		out := make([]byte, 0, len(buf)-(after-start)+len(block)+1)
		out = append(out, buf[:start]...)
		out = append(out, block...)
		if after < len(buf) {
			out = append(out, '\n')
		}
		out = append(out, buf[after:]...)
		return out
	}

	// Preserve a valid existing shebang and inject directly after it.
	if bytes.HasPrefix(buf, []byte("#!")) {
		if nl := bytes.IndexByte(buf, '\n'); nl >= 0 {
			out := make([]byte, 0, len(buf)+len(block)+1)
			out = append(out, buf[:nl+1]...)
			out = append(out, block...)
			out = append(out, '\n')
			out = append(out, buf[nl+1:]...)
			return out
		}
	}

	// Missing/empty/non-shebang hooks are still safe to extend: the synthetic
	// wrapper is explicitly marked as ctrld-owned and cleanup removes it.
	marked := merlinBlockWithSyntheticShebang(block)
	out := make([]byte, 0, len(buf)+len(marked)+16)
	out = append(out, "#!/bin/sh\n"...)
	out = append(out, marked...)
	out = append(out, '\n')
	out = append(out, buf...)
	return out
}

// atomicWriteFile replaces path only after a complete sibling temporary file
// has been written, synced, closed and chmodded. This avoids truncating a shared
// Merlin hook if JFFS fills up or a short write occurs.
func atomicWriteFile(path string, data []byte, mode os.FileMode) (err error) {
	target := path
	if info, lstatErr := os.Lstat(path); lstatErr == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err = filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
	} else if lstatErr != nil && !os.IsNotExist(lstatErr) {
		return lstatErr
	}

	writeMode := mode
	if info, statErr := os.Stat(target); statErr == nil {
		writeMode = info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	} else if !os.IsNotExist(statErr) {
		return statErr
	}

	dir := filepath.Dir(target)
	base := filepath.Base(target)
	tmp, err := os.CreateTemp(dir, "."+base+".ctrld-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()

	if err = tmp.Chmod(writeMode); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}
	if err = syncParentDir(dir); err != nil {
		return err
	}
	return nil
}

func syncParentDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		if runtime.GOOS == "windows" {
			return nil
		}
		return err
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func removeFileDurable(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncParentDir(filepath.Dir(path))
}

// waitDirExists waits until the specified directory exists, polling its existence every second.
func waitDirExists(dir string) {
	for {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			return
		}
		time.Sleep(time.Second)
	}
}
