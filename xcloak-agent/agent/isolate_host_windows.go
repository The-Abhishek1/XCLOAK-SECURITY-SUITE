//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// IsolateHost on Windows uses Windows Defender Firewall (netsh advfirewall)
// to block all inbound and outbound traffic except to/from the XCloak
// management server and loopback.
//
// Requires the agent to run as Administrator or LocalSystem.
// A PowerShell rollback script is written to %TEMP%\xcloak-isolate-rollback.ps1.
func IsolateHost(task models.AgentTask) error {

	var payload IsolatePayload
	json.Unmarshal(task.Payload, &payload)

	if _, err := exec.LookPath("netsh"); err != nil {
		return fmt.Errorf("netsh not found — is the agent running as Administrator?")
	}

	fmt.Println("[isolate] Applying network isolation (Windows/WDF)...")

	// ── 1. Block all inbound and outbound by default ──────────────
	// We set the profile rules for Domain, Private, and Public.
	for _, profile := range []string{"domain", "private", "public"} {
		if out, err := exec.Command("netsh", "advfirewall", "set",
			profile+"profile", "firewallpolicy",
			"blockinbound,blockoutbound",
		).CombinedOutput(); err != nil {
			return fmt.Errorf("netsh set %s policy failed: %s — %s", profile, err, string(out))
		}
	}

	// ── 2. Remove any prior XCloak isolation rules ────────────────
	exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name=XCloak-Isolate-Allow").Run()

	// ── 3. Allow loopback (127.0.0.1 / ::1) ─────────────────────
	for _, dir := range []string{"in", "out"} {
		exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name=XCloak-Isolate-Allow-Loopback",
			"dir="+dir, "action=allow", "enable=yes",
			"protocol=any", "remoteip=127.0.0.1,::1",
		).Run()
	}

	// ── 4. Allow management IPs ──────────────────────────────────
	for _, ip := range payload.AllowIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		for _, dir := range []string{"in", "out"} {
			if out, err := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
				"name=XCloak-Isolate-Allow",
				"dir="+dir, "action=allow", "enable=yes",
				"protocol=any",
				"remoteip="+ip,
			).CombinedOutput(); err != nil {
				fmt.Printf("[isolate] warn: could not allow %s %s: %s — %s\n",
					ip, dir, err, string(out))
			}
		}
	}

	// ── 5. Write PowerShell rollback script ───────────────────────
	rollback := `# XCloak isolation rollback
# Run as Administrator: powershell -ExecutionPolicy Bypass -File xcloak-isolate-rollback.ps1
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
netsh advfirewall firewall delete rule name="XCloak-Isolate-Allow"
netsh advfirewall firewall delete rule name="XCloak-Isolate-Allow-Loopback"
Write-Host "Network isolation lifted"
`
	rollbackPath := os.TempDir() + `\xcloak-isolate-rollback.ps1`
	os.WriteFile(rollbackPath, []byte(rollback), 0644)

	fmt.Printf("[isolate] Host isolated. Rollback: powershell -File %s\n", rollbackPath)
	return nil
}
