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
	"unicode"

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

	// Restore old configs.
	if err := nvram.Restore(nvramKvMap, nvram.CtrldSetupKey); err != nil {
		return err
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

	return os.WriteFile(path, merlinUpsertPostConf(buf, []byte(block)), 0750)
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

	return os.WriteFile(path, clean, 0750)
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

// merlinParsePostConf removes ctrld-owned postconf content while preserving unrelated hook logic.
// It understands both the current BEGIN/END block and the legacy ctrld <= 1.5.7 EOF marker format.
func merlinParsePostConf(buf []byte) []byte {
	if len(buf) == 0 {
		return nil
	}

	begin := []byte(dnsmasq.MerlinPostConfBeginMarker)
	end := []byte(dnsmasq.MerlinPostConfEndMarker)
	if start := bytes.Index(buf, begin); start >= 0 {
		if relEnd := bytes.Index(buf[start+len(begin):], end); relEnd >= 0 {
			finish := start + len(begin) + relEnd + len(end)
			for finish < len(buf) && (buf[finish] == '\r' || buf[finish] == '\n') {
				finish++
			}
			out := make([]byte, 0, len(buf)-(finish-start))
			out = append(out, buf[:start]...)
			out = append(out, buf[finish:]...)
			return bytes.TrimRight(out, "\r\n")
		}
	}

	// Legacy format put the ctrld-generated script before an EOF marker and
	// preserved the previous hook content after that marker.
	parts := bytes.SplitN(buf, []byte(dnsmasq.MerlinPostConfMarker), 2)
	if len(parts) == 2 {
		return bytes.TrimLeftFunc(parts[1], unicode.IsSpace)
	}
	return buf
}

// merlinUpsertPostConf replaces only ctrld's marked block and keeps other hook content.
// ctrld's block is inserted immediately after an existing shebang, otherwise a shell shebang is added.
func merlinUpsertPostConf(buf, block []byte) []byte {
	clean := merlinParsePostConf(buf)
	clean = bytes.TrimRight(clean, "\r\n")

	if len(clean) == 0 {
		return []byte("#!/bin/sh\n\n" + string(block) + "\n")
	}

	if bytes.HasPrefix(clean, []byte("#!")) {
		if nl := bytes.IndexByte(clean, '\n'); nl >= 0 {
			head := clean[:nl+1]
			rest := bytes.TrimLeft(clean[nl+1:], "\r\n")
			out := make([]byte, 0, len(clean)+len(block)+4)
			out = append(out, head...)
			out = append(out, '\n')
			out = append(out, block...)
			if len(rest) > 0 {
				out = append(out, '\n', '\n')
				out = append(out, rest...)
			}
			out = append(out, '\n')
			return out
		}
	}

	return []byte("#!/bin/sh\n\n" + string(block) + "\n\n" + string(clean) + "\n")
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
