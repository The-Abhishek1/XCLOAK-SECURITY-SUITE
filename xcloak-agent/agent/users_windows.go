//go:build windows

package agent

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectUsers on Windows enumerates local user accounts via `net user`
// and marks which are enabled, administrators, or recently logged in.
// Active Directory domain accounts are not enumerated (use identity provider
// integration for that — a future XDR feature).
func CollectUsers(agentID int) {

	// net user /domain would list domain users, but we scope to local only.
	out, err := exec.Command("net", "user").Output()
	if err != nil {
		fmt.Println("[collector] users: net user failed:", err)
		collectUsersViaCIM(agentID) // fallback
		return
	}

	var users []models.User
	inUserSection := false

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")

		// The user list starts after the "----" separator.
		if strings.Contains(line, "---") {
			inUserSection = true
			continue
		}
		if !inUserSection {
			continue
		}
		// Empty line or "command completed" ends the list.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "The command") {
			break
		}

		// Each line has up to 3 usernames separated by whitespace.
		for _, username := range strings.Fields(trimmed) {
			if username == "" {
				continue
			}
			users = append(users, models.User{
				AgentID:  agentID,
				Username: username,
				UID:      0, // Windows SIDs not directly comparable to Unix UIDs
				Shell:    "cmd", // default; PowerShell users may differ
			})
		}
	}

	if len(users) == 0 {
		collectUsersViaCIM(agentID)
		return
	}

	body, _ := json.Marshal(users)
	resp, err := authPost("/api/agents/users", body)
	if err != nil {
		fmt.Println("[collector] users: send failed:", err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[collector] users: sent %d\n", len(users))
}

// collectUsersViaCIM is a PowerShell fallback for systems where net.exe
// output format differs (localised Windows versions).
func collectUsersViaCIM(agentID int) {

	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json -Compress`,
	).Output()
	if err != nil {
		fmt.Println("[collector] users: CIM fallback failed:", err)
		return
	}

	type localUser struct {
		Name    string `json:"Name"`
		Enabled bool   `json:"Enabled"`
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return
	}

	var items []localUser
	if strings.HasPrefix(raw, "[") {
		json.Unmarshal([]byte(raw), &items)
	} else {
		var single localUser
		if err := json.Unmarshal([]byte(raw), &single); err == nil {
			items = []localUser{single}
		}
	}

	var users []models.User
	for _, item := range items {
		shell := "cmd"
		if !item.Enabled {
			shell = "disabled"
		}
		users = append(users, models.User{
			AgentID:  agentID,
			Username: item.Name,
			UID:      0,
			Shell:    shell,
		})
	}

	if len(users) == 0 {
		return
	}

	body, _ := json.Marshal(users)
	resp, err := authPost("/api/agents/users", body)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[collector] users (CIM): sent %d\n", len(users))
}
