package merlin

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"

	"github.com/Control-D-Inc/ctrld"
	"github.com/Control-D-Inc/ctrld/internal/router/dnsmasq"
	"github.com/Control-D-Inc/ctrld/internal/router/ntp"
	"github.com/Control-D-Inc/ctrld/internal/router/nvram"
)

const Name = "merlin"

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
	// Wait NTP ready.
	_ = m.Cleanup()
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
func (m *Merlin) Setup() error {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	// Already setup.
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val == "1" {
		return nil
	}

	if err := m.writeDnsmasqPostconf(); err != nil {
		return err
	}

	for _, cfg := range getDnsmasqConfigs() {
		if err := m.setupDnsmasq(cfg); err != nil {
			return fmt.Errorf("failed to setup dnsmasq: config: %s, error: %w", cfg.confPath, err)
		}
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}

	if err := nvram.SetKV(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	return nil
}

// Cleanup restores the original dnsmasq and nvram configurations and restarts dnsmasq if necessary.
func (m *Merlin) Cleanup() error {
	if m.cfg.FirstListener().IsDirectDnsListener() {
		return nil
	}
	if val, _ := nvram.Run("get", nvram.CtrldSetupKey); val != "1" {
		return nil // was restored, nothing to do.
	}

	for _, path := range []string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath} {
		if err := cleanupDnsmasqPostconf(path); err != nil {
			return err
		}
	}

	for _, cfg := range getDnsmasqConfigs() {
		if err := m.cleanupDnsmasqJffs(cfg); err != nil {
			return fmt.Errorf("failed to cleanup jffs dnsmasq: config: %s, error: %w", cfg.confPath, err)
		}
	}

	// Restore NVRAM only after ctrld-owned artifacts are cleaned successfully.
	// Keeping ctrld_setup set until this point makes a failed cleanup retryable.
	if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
	}

	// Restart dnsmasq service.
	if err := restartDNSMasq(); err != nil {
		return err
	}
	return nil
}

// setupDnsmasq sets up dnsmasq configuration by writing postconf, copying configuration, and running a postconf script.
func (m *Merlin) setupDnsmasq(cfg *dnsmasqConfig) error {
	src, err := os.Open(cfg.confPath)
	if os.IsNotExist(err) {
		return nil // nothing to do if conf file does not exist.
	}
	if err != nil {
		return fmt.Errorf("failed to open dnsmasq config: %w", err)
	}
	defer src.Close()

	// Copy current dnsmasq config to cfg.jffsConfPath,
	// Then we will run postconf script on this file.
	//
	// Normally, adding postconf script is enough. However, we see
	// reports on some Merlin devices that postconf scripts does not
	// work, but manipulating the config directly via /jffs/configs does.
	dst, err := os.Create(cfg.jffsConfPath)
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", cfg.jffsConfPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("failed to copy current dnsmasq config: %w", err)
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("failed to save %s: %w", cfg.jffsConfPath, err)
	}

	// Run the appropriate postconf script on cfg.jffsConfPath directly.
	postConfPath := dnsmasq.MerlinPostConfPath
	if cfg.confPath != dnsmasq.MerlinConfPath {
		postConfPath = dnsmasq.MerlinSdnPostConfPath
	}
	cmd := exec.Command("/bin/sh", postConfPath, cfg.jffsConfPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to run post conf: %s: %w", string(out), err)
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

// writeDnsmasqPostconf installs ctrld-owned blocks in Merlin's main and SDN hooks while preserving unrelated content.
func (m *Merlin) writeDnsmasqPostconf() error {
	for _, path := range []string{dnsmasq.MerlinPostConfPath, dnsmasq.MerlinSdnPostConfPath} {
		if err := m.writeDnsmasqPostconfFile(path); err != nil {
			return err
		}
	}
	return nil
}

func (m *Merlin) writeDnsmasqPostconfFile(path string) error {
	buf, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	data, err := dnsmasq.ConfTmpl(dnsmasq.MerlinPostConfTmpl, m.cfg)
	if err != nil {
		return err
	}

	block := strings.Join([]string{
		dnsmasq.MerlinPostConfBeginMarker,
		strings.TrimSpace(data),
		dnsmasq.MerlinPostConfEndMarker,
	}, "\n")

	return atomicWriteFile(path, merlinUpsertPostConf(buf, []byte(block)), 0750)
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
	if len(bytes.TrimSpace(clean)) == 0 || bytes.Equal(bytes.TrimSpace(clean), []byte("#!/bin/sh")) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}

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

// merlinPostConfBlock returns the ctrld-owned block bounds.
// It understands both the current BEGIN/END format and the legacy <= 1.5.7
// GENERATED/EOF format. Legacy matching is deliberately bounded by the known
// ctrld header so content prepended by another addon is not treated as ours.
func merlinPostConfBlock(buf []byte) (start, end int, ok bool) {
	begin := []byte(dnsmasq.MerlinPostConfBeginMarker)
	endMarker := []byte(dnsmasq.MerlinPostConfEndMarker)
	if start = bytes.Index(buf, begin); start >= 0 {
		relEnd := bytes.Index(buf[start+len(begin):], endMarker)
		if relEnd >= 0 {
			end = start + len(begin) + relEnd + len(endMarker)
			return start, end, true
		}
	}

	legacyEnd := []byte(dnsmasq.MerlinPostConfMarker)
	if marker := bytes.Index(buf, legacyEnd); marker >= 0 {
		legacyBegin := []byte(dnsmasq.CtrldMarker)
		if relStart := bytes.LastIndex(buf[:marker], legacyBegin); relStart >= 0 {
			return relStart, marker + len(legacyEnd), true
		}
	}

	return 0, 0, false
}

// merlinParsePostConf removes only ctrld-owned postconf content while preserving
// unrelated hook logic before and after it.
func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}
	start, end, ok := merlinPostConfBlock(buf)
	if !ok {
		return buf
	}

	out := make([]byte, 0, len(buf)-(end-start))
	out = append(out, buf[:start]...)
	out = append(out, buf[end:]...)
	return bytes.TrimRight(out, "\r\n")
}

// merlinUpsertPostConf replaces an existing ctrld block in place, preserving
// ordering relative to other addons. On first install, it places ctrld directly
// after an existing shebang, or creates a shell shebang if one is absent.
func merlinUpsertPostConf(buf, block []byte) []byte {
	if start, end, ok := merlinPostConfBlock(buf); ok {
		out := make([]byte, 0, len(buf)-(end-start)+len(block))
		out = append(out, buf[:start]...)
		out = append(out, block...)
		out = append(out, buf[end:]...)
		return out
	}

	clean := bytes.TrimRight(buf, "\r\n")
	if len(clean) == 0 {
		return []byte("#!/bin/sh\n\n" + string(block) + "\n")
	}

	if bytes.HasPrefix(clean, []byte("#!")) {
		if nl := bytes.IndexByte(clean, '\n'); nl >= 0 {
			head := clean[:nl+1]
			rest := clean[nl+1:]
			out := make([]byte, 0, len(clean)+len(block)+4)
			out = append(out, head...)
			out = append(out, '\n')
			out = append(out, block...)
			if len(rest) > 0 {
				out = append(out, '\n')
				out = append(out, rest...)
			}
			out = append(out, '\n')
			return out
		}
	}

	return []byte("#!/bin/sh\n\n" + string(block) + "\n\n" + string(clean) + "\n")
}

// atomicWriteFile replaces path only after a complete sibling temporary file
// has been written, synced, closed and chmodded. This avoids truncating a shared
// Merlin hook if JFFS fills up or a short write occurs.
func atomicWriteFile(path string, data []byte, mode os.FileMode) (err error) {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
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

	if err = tmp.Chmod(mode); err != nil {
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
	if err = os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
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
