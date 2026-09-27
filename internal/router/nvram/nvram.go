package nvram

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const (
	CtrldKeyPrefix  = "ctrld_"
	CtrldSetupKey   = "ctrld_setup"
	CtrldInstallKey = "ctrld_install"
	RCStartupKey    = "rc_startup"
)

// Run runs the given nvram command.
func Run(args ...string) (string, error) {
	cmd := exec.Command("nvram", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s:%w", stderr.String(), err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

/*
NOTE:
  - For Openwrt, DNSSEC is not included in default dnsmasq (require dnsmasq-full).
  - For Merlin, DNSSEC is configured during postconf script (see merlinDNSMasqPostConfTmpl).
  - For Ubios UDM Pro/Dream Machine, DNSSEC is not included in their dnsmasq package:
    +https://community.ui.com/questions/Implement-DNSSEC-into-UniFi/951c72b0-4d88-4c86-9174-45417bd2f9ca
    +https://community.ui.com/questions/Enable-DNSSEC-for-Unifi-Dream-Machine-FW-updates/e68e367c-d09b-4459-9444-18908f7c1ea1
*/

// SetKV writes the given key/value from map to nvram.
// The given setupKey is set to 1 to indicate key/value set.
//
// NVRAM mutations are not transactional. Keep enough rollback information in
// volatile NVRAM and restore it on any failure so callers never have to infer
// whether a partially failed sequence changed router state.
func SetKV(m map[string]string, setupKey string) error {
	modified := make([]string, 0, len(m))

	rollback := func(cause error) error {
		var restoreErr error
		for i := len(modified) - 1; i >= 0; i-- {
			key := modified[i]
			ctrldKey := CtrldKeyPrefix + key
			old, err := Run("get", ctrldKey)
			if err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("read rollback %s: %w", ctrldKey, err))
				continue
			}
			if out, err := Run("set", key+"="+old); err != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("%s: %w", out, err))
			}
		}

		if restoreErr != nil {
			// At least one ctrld-modified value may still be active. Keep an
			// explicit setup marker so Merlin Cleanup/Restore will retry from the
			// retained ctrld_* backup values instead of treating the state as clean.
			var markerErr error
			if out, err := Run("set", setupKey+"=1"); err != nil {
				markerErr = errors.Join(markerErr, fmt.Errorf("%s: %w", out, err))
			}
			if out, err := Run("commit"); err != nil {
				markerErr = errors.Join(markerErr, fmt.Errorf("%s: %w", out, err))
			}
			return errors.Join(
				cause,
				fmt.Errorf("nvram rollback incomplete: %w", restoreErr),
				markerErr,
			)
		}

		if out, err := Run("unset", setupKey); err != nil {
			return errors.Join(cause, fmt.Errorf("%s: %w", out, err))
		}
		if _, err := Run("commit"); err != nil {
			// The restored values may only be volatile. Re-arm the marker before
			// returning so the caller's deferred Cleanup has a retryable state.
			var markerErr error
			if out, setErr := Run("set", setupKey+"=1"); setErr != nil {
				markerErr = errors.Join(markerErr, fmt.Errorf("%s: %w", out, setErr))
			}
			if out, commitErr := Run("commit"); commitErr != nil {
				markerErr = errors.Join(markerErr, fmt.Errorf("%s: %w", out, commitErr))
			}
			return errors.Join(
				cause,
				fmt.Errorf("nvram rollback commit failed: %w", err),
				markerErr,
			)
		}
		return cause
	}

	fail := func(err error) error {
		if len(modified) == 0 {
			return err
		}
		return rollback(err)
	}

	for key, value := range m {
		old, err := Run("get", key)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", old, err))
		}
		if out, err := Run("set", CtrldKeyPrefix+key+"="+old); err != nil {
			return fail(fmt.Errorf("%s: %w", out, err))
		}
		modified = append(modified, key)
		if out, err := Run("set", key+"="+value); err != nil {
			return rollback(fmt.Errorf("%s: %w", out, err))
		}
	}

	if out, err := Run("set", setupKey+"=1"); err != nil {
		return rollback(fmt.Errorf("%s: %w", out, err))
	}
	if out, err := Run("commit"); err != nil {
		return rollback(fmt.Errorf("%s: %w", out, err))
	}
	return nil
}

// Restore restores the old value of each key from ctrld's backup NVRAM.
// Backup keys are deliberately retained after the restore commit. They are tiny,
// harmless, and keeping them avoids a second non-transactional "cleanup commit"
// that could destroy the only rollback copy after a transient nvram failure.
// A future SetKV overwrites each backup with the then-current value.
func Restore(m map[string]string, setupKey string) error {
	for key := range m {
		ctrldKey := CtrldKeyPrefix + key
		old, err := Run("get", ctrldKey)
		if err != nil {
			return fmt.Errorf("%s: %w", old, err)
		}
		if out, err := Run("set", key+"="+old); err != nil {
			return fmt.Errorf("%s: %w", out, err)
		}
	}

	if out, err := Run("unset", setupKey); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}
	if out, err := Run("commit"); err != nil {
		// The persistent commit may have failed while the volatile nvram view
		// already has setupKey unset. Re-arm setupKey only in volatile NVRAM so
		// Merlin Cleanup will retry Restore in this boot, but deliberately do not
		// commit the marker: if the restored values actually reached persistent
		// storage despite the reported error, a reboot must not resurrect a
		// completed ctrld setup transaction.
		commitErr := fmt.Errorf("%s: %w", out, err)
		if markerOut, markerErr := Run("set", setupKey+"=1"); markerErr != nil {
			return errors.Join(
				commitErr,
				fmt.Errorf("failed to re-arm volatile %s after restore commit failure: %s: %w", setupKey, markerOut, markerErr),
			)
		}
		return commitErr
	}
	return nil
}
