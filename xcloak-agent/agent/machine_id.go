package agent

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
)

// MachineID returns a stable identifier for this machine that survives reboots
// and agent restarts. It is derived from:
//   1. /etc/machine-id  (systemd — present on all modern Linux distros)
//   2. /proc/sys/kernel/random/boot_id  (fallback, changes on reboot but better than nothing)
//   3. hostname (last resort)
//
// The value is SHA256-hashed so we never send raw system identifiers to the server.
func MachineID() string {

	raw := readMachineIDRaw()

	hash := sha256.Sum256([]byte(raw))

	return fmt.Sprintf("%x", hash)
}

func readMachineIDRaw() string {

	// 1. systemd machine-id — stable across reboots
	if id := readFile("/etc/machine-id"); id != "" {
		return id
	}

	// 2. kernel boot_id — changes on reboot, but unique per session
	if id := readFile("/proc/sys/kernel/random/boot_id"); id != "" {
		return id
	}

	// 3. hostname — least stable, but always available
	if hostname, err := os.Hostname(); err == nil {
		return hostname
	}

	return "unknown"
}

func readFile(path string) string {

	b, err := os.ReadFile(path)

	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}
