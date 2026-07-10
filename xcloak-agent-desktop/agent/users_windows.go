//go:build windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"

	"xcloak-agent-desktop/models"
)

// CollectUsers on Windows enumerates local user accounts via `net user`,
// including enabled status and admin group membership.
func CollectUsers(agentID int) {
	out, err := exec.Command("net", "user").Output()
	if err != nil {
		slog.Warn("net user failed, trying PowerShell CIM", "err", err)
		collectUsersViaCIM(agentID)
		return
	}

	var users []models.User
	inUserSection := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "---") {
			inUserSection = true
			continue
		}
		if !inUserSection {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "The command") {
			break
		}
		for _, username := range strings.Fields(trimmed) {
			if username == "" {
				continue
			}
			users = append(users, models.User{
				AgentID:  agentID,
				Username: username,
				Shell:    "cmd",
				Enabled:  true,
			})
		}
	}

	if len(users) == 0 {
		collectUsersViaCIM(agentID)
		return
	}

	// Enrich with admin group membership
	adminMembers := getLocalAdminMembers()
	for i := range users {
		if adminMembers[users[i].Username] {
			users[i].SudoAccess = true
		}
	}

	body, _ := json.Marshal(users)
	resp, err := authPost("/api/agents/users", body)
	if err != nil {
		slog.Error("users: send failed", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("users sent", "count", len(users))
}

// getLocalAdminMembers returns the set of usernames in the local Administrators group.
func getLocalAdminMembers() map[string]bool {
	m := make(map[string]bool)
	out, err := exec.Command("net", "localgroup", "Administrators").Output()
	if err != nil {
		return m
	}
	inMembers := false
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.Contains(line, "---") {
			inMembers = true
			continue
		}
		if !inMembers {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "The command") {
			break
		}
		m[trimmed] = true
	}
	return m
}

// collectUsersViaCIM is a PowerShell fallback for systems where net.exe
// output format differs (localised Windows versions).
func collectUsersViaCIM(agentID int) {
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-LocalUser | Select-Object Name,Enabled,Description | ConvertTo-Json -Compress`,
	).Output()
	if err != nil {
		slog.Error("users: CIM fallback failed", "err", err)
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

	adminMembers := getLocalAdminMembers()
	var users []models.User
	for _, item := range items {
		users = append(users, models.User{
			AgentID:    agentID,
			Username:   item.Name,
			Shell:      "cmd",
			Enabled:    item.Enabled,
			SudoAccess: adminMembers[item.Name],
		})
	}

	if len(users) == 0 {
		return
	}
	body, _ := json.Marshal(users)
	resp, err := authPost("/api/agents/users", body)
	if err != nil {
		slog.Error("users (CIM): send failed", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("users sent via CIM", "count", len(users))
}
