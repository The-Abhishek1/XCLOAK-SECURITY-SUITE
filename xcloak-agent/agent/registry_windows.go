//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RegistryEntry represents a single registry value captured during a scan.
type RegistryEntry struct {
	AgentID  int    `json:"agent_id"`
	Hive     string `json:"hive"`     // e.g. "HKLM"
	KeyPath  string `json:"key_path"` // e.g. "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
	Name     string `json:"name"`     // value name
	Type     string `json:"type"`     // REG_SZ, REG_DWORD, etc.
	Data     string `json:"data"`     // value data
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistence key paths — the locations most commonly abused for persistence.
// This list covers T1547.001 (Registry Run Keys) and related sub-techniques.
// ─────────────────────────────────────────────────────────────────────────────

var persistenceKeys = []string{
	// Run keys — execute on every user logon
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	// 32-bit on 64-bit Windows
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
	// Services — used for service-based persistence (T1543.003)
	`HKLM\SYSTEM\CurrentControlSet\Services`,
	// Winlogon — can be hijacked to run code at login (T1547.004)
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	// Image File Execution Options — debugger hijacking (T1546.012)
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
	// AppInit_DLLs — DLL injection at process start (T1546.010)
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
	// Scheduled Tasks registry keys
	`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`,
	// Boot Execute — runs before user space (T1547.001)
	`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`,
}

// ─────────────────────────────────────────────────────────────────────────────
// CollectRegistryPersistence scans persistence key paths, collects their
// values, and ships them to the server. Called from StartCollectors every hour.
// ─────────────────────────────────────────────────────────────────────────────

func CollectRegistryPersistence(agentID int) {

	var entries []RegistryEntry

	for _, keyPath := range persistenceKeys {
		vals, err := queryRegistryKey(keyPath)
		if err != nil {
			// Key may not exist on all Windows versions — skip silently.
			continue
		}
		for _, v := range vals {
			v.AgentID = agentID
			entries = append(entries, v)
		}
	}

	if len(entries) == 0 {
		return
	}

	body, _ := json.Marshal(entries)
	resp, err := authPost("/api/agents/registry", body)
	if err != nil {
		fmt.Println("[collector] registry: send failed:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("[collector] registry: sent %d entries\n", len(entries))
}

// ─────────────────────────────────────────────────────────────────────────────
// queryRegistryKey runs `reg query <keyPath>` and parses the output.
// Returns one RegistryEntry per value found under the key.
// ─────────────────────────────────────────────────────────────────────────────

func queryRegistryKey(keyPath string) ([]RegistryEntry, error) {

	out, err := exec.Command("reg", "query", keyPath).Output()
	if err != nil {
		return nil, err
	}

	// Split hive from path for structured storage.
	hive, rest := splitHive(keyPath)

	var entries []RegistryEntry

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "HKEY") {
			continue
		}

		// reg query output: "    ValueName    REG_TYPE    Data"
		// Fields are tab-separated with leading spaces.
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		name    := fields[0]
		regType := fields[1]
		data    := strings.Join(fields[2:], " ")

		entries = append(entries, RegistryEntry{
			Hive:    hive,
			KeyPath: rest,
			Name:    name,
			Type:    regType,
			Data:    data,
		})
	}

	return entries, nil
}

// splitHive separates "HKLM" from the rest of a registry path.
func splitHive(keyPath string) (hive, rest string) {
	parts := strings.SplitN(keyPath, `\`, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return keyPath, ""
}
