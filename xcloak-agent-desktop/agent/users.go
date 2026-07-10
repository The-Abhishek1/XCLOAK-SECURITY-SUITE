//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"xcloak-agent-desktop/models"
)

// CollectUsers builds an enriched user inventory from /etc/passwd + /etc/group
// + sudoers + SSH authorized_keys + last login timestamps.
func CollectUsers(agentID int) {
	users := parsePasswd(agentID)
	if len(users) == 0 {
		slog.Warn("no users found in /etc/passwd")
		return
	}

	groupMap := parseGroupFile()     // username → []groupName
	sudoUsers := parseSudoers()      // set of usernames with sudo

	for i := range users {
		u := &users[i]
		u.Groups = groupMap[u.Username]
		u.SudoAccess = sudoUsers[u.Username]
		u.HasSSHKey = hasAuthorizedKeys(u.HomeDir)
		u.LastLogin = getLastLogin(u.Username)
		u.Enabled = isAccountEnabled(u.Username)
	}

	body, _ := json.Marshal(users)
	resp, err := authPost("/api/agents/users", body)
	if err != nil {
		slog.Error("failed sending users", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("users sent", "count", len(users))
}

func parsePasswd(agentID int) []models.User {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		slog.Error("failed to open /etc/passwd", "err", err)
		return nil
	}
	defer f.Close()

	var users []models.User
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		users = append(users, models.User{
			AgentID:  agentID,
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  fields[5],
			Shell:    fields[6],
			Enabled:  true,
		})
	}
	return users
}

// parseGroupFile returns a map from username to list of supplementary group names.
func parseGroupFile() map[string][]string {
	m := make(map[string][]string)
	f, err := os.Open("/etc/group")
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		members := strings.Split(fields[3], ",")
		for _, member := range members {
			member = strings.TrimSpace(member)
			if member == "" {
				continue
			}
			m[member] = append(m[member], groupName)
		}
	}
	return m
}

// parseSudoers scans /etc/sudoers and /etc/sudoers.d/* for user privilege grants.
func parseSudoers() map[string]bool {
	sudo := make(map[string]bool)
	files := []string{"/etc/sudoers"}
	if entries, err := filepath.Glob("/etc/sudoers.d/*"); err == nil {
		files = append(files, entries...)
	}
	for _, path := range files {
		scanSudoersFile(path, sudo)
	}
	// Also treat any user in the "sudo" or "wheel" group as having sudo access —
	// distros grant NOPASSWD via group membership rather than explicit sudoers lines.
	groupF, err := os.Open("/etc/group")
	if err != nil {
		return sudo
	}
	defer groupF.Close()
	sc := bufio.NewScanner(groupF)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "sudo" || fields[0] == "wheel" || fields[0] == "admin" {
			for _, member := range strings.Split(fields[3], ",") {
				if m := strings.TrimSpace(member); m != "" {
					sudo[m] = true
				}
			}
		}
	}
	return sudo
}

func scanSudoersFile(path string, out map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		// Lines starting with % are group entries
		if strings.HasPrefix(line, "%") {
			continue
		}
		// "username ALL=..." form
		parts := strings.Fields(line)
		if len(parts) >= 2 && strings.Contains(line, "ALL") {
			out[parts[0]] = true
		}
	}
}

// hasAuthorizedKeys checks whether the user has any SSH authorized_keys.
func hasAuthorizedKeys(homeDir string) bool {
	if homeDir == "" || homeDir == "/" {
		return false
	}
	info, err := os.Stat(filepath.Join(homeDir, ".ssh", "authorized_keys"))
	return err == nil && info.Size() > 0
}

// getLastLogin runs `last -n 1 <username>` to find the most recent login.
func getLastLogin(username string) string {
	out, err := exec.Command("last", "-n", "1", username).Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	// first line is the most recent login
	line := strings.TrimSpace(lines[0])
	if strings.HasPrefix(line, username) {
		// strip the username prefix
		parts := strings.Fields(line)
		if len(parts) >= 5 {
			return strings.Join(parts[3:7], " ")
		}
		return line
	}
	return ""
}

// isAccountEnabled checks /etc/shadow for "!" or "*" in the password field
// (meaning the account is locked/disabled).
func isAccountEnabled(username string) bool {
	f, err := os.Open("/etc/shadow")
	if err != nil {
		return true // can't read shadow — assume enabled
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), ":")
		if len(fields) < 2 || fields[0] != username {
			continue
		}
		pw := fields[1]
		return pw != "!" && pw != "!!" && pw != "*" && pw != ""
	}
	return true
}
