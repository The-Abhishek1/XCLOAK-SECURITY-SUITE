//go:build windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectPackages on Windows enumerates installed software via WMIC and,
// if available, winget. WMIC covers all MSI/registry-installed software;
// winget covers Microsoft Store and winget-managed packages.
//
// Falls back to querying the Uninstall registry keys via PowerShell if WMIC
// is unavailable (Windows 11 22H2+).
func CollectPackages(agentID int) {

	packages := collectPackagesViaWMIC(agentID)
	if len(packages) == 0 {
		packages = collectViaRegistry(agentID)
	}

	// Optionally append winget packages (not available everywhere).
	packages = append(packages, collectViaWinget(agentID)...)

	if len(packages) == 0 {
		slog.Warn("no packages found on Windows")
		return
	}

	body, _ := json.Marshal(packages)
	resp, err := authPost("/api/agents/packages", body)
	if err != nil {
		slog.Error("packages: send failed", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("packages sent", "count", len(packages))
}

// collectPackagesViaWMIC uses `wmic product get Name,Version /FORMAT:CSV`.
func collectPackagesViaWMIC(agentID int) []models.Package {

	out, err := exec.Command(
		"wmic", "product", "get", "Name,Version", "/FORMAT:CSV",
	).Output()
	if err != nil {
		return nil
	}

	var packages []models.Package
	lines := strings.Split(string(out), "\n")
	headerIdx := -1
	var headers []string

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(strings.ToLower(line), "name") &&
			strings.Contains(strings.ToLower(line), "version") {
			headers = splitCSV(line)
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 {
		return nil
	}

	nameIdx, verIdx := -1, -1
	for i, h := range headers {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "name" { nameIdx = i }
		if h == "version" { verIdx = i }
	}
	if nameIdx < 0 {
		return nil
	}

	for _, line := range lines[headerIdx+1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitCSV(line)
		if len(fields) <= nameIdx {
			continue
		}
		name := strings.TrimSpace(fields[nameIdx])
		ver  := ""
		if verIdx >= 0 && verIdx < len(fields) {
			ver = strings.TrimSpace(fields[verIdx])
		}
		if name == "" {
			continue
		}
		packages = append(packages, models.Package{
			AgentID:     agentID,
			PackageName: name,
			Version:     ver,
			Source:      "wmic",
		})
	}
	return packages
}

// collectViaRegistry queries the Uninstall registry keys via PowerShell.
// This is the fallback for Windows 11 22H2+ where WMIC is removed.
func collectViaRegistry(agentID int) []models.Package {

	script := `
$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $paths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -ne $null } |
  Select-Object DisplayName, DisplayVersion |
  ConvertTo-Json -Compress
`
	out, err := exec.Command(
		"powershell", "-NoProfile", "-NonInteractive", "-Command", script,
	).Output()
	if err != nil {
		slog.Error("packages: registry fallback failed", "err", err)
		return nil
	}

	type regPkg struct {
		Name    string `json:"DisplayName"`
		Version string `json:"DisplayVersion"`
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil
	}

	var items []regPkg
	if strings.HasPrefix(raw, "[") {
		json.Unmarshal([]byte(raw), &items)
	} else {
		var single regPkg
		if err := json.Unmarshal([]byte(raw), &single); err == nil {
			items = []regPkg{single}
		}
	}

	packages := make([]models.Package, 0, len(items))
	for _, item := range items {
		if item.Name == "" {
			continue
		}
		packages = append(packages, models.Package{
			AgentID:     agentID,
			PackageName: item.Name,
			Version:     item.Version,
			Source:      "registry",
		})
	}
	return packages
}

// collectViaWinget enumerates winget-managed packages.
// winget is not available on all systems so errors are silently ignored.
func collectViaWinget(agentID int) []models.Package {

	out, err := exec.Command("winget", "list", "--accept-source-agreements").Output()
	if err != nil {
		return nil
	}

	var packages []models.Package
	lines := strings.Split(string(out), "\n")
	headerSeen := false

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if !headerSeen {
			if strings.Contains(line, "Name") && strings.Contains(line, "Version") {
				headerSeen = true
			}
			continue
		}
		// Skip separator line (----)
		if strings.HasPrefix(strings.TrimSpace(line), "---") {
			continue
		}
		// winget uses fixed-width columns — split by 2+ spaces
		parts := splitFixedWidth(line)
		if len(parts) < 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		ver  := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}
		packages = append(packages, models.Package{
			AgentID:     agentID,
			PackageName: name,
			Version:     ver,
			Source:      "winget",
		})
	}
	return packages
}

// splitFixedWidth splits a winget-style fixed-width line by 2+ space runs.
func splitFixedWidth(line string) []string {
	var parts []string
	var cur strings.Builder
	spaceRun := 0
	for _, ch := range line {
		if ch == ' ' {
			spaceRun++
			if spaceRun >= 2 && cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
				spaceRun = 0
			}
		} else {
			if spaceRun > 0 && cur.Len() == 0 {
				spaceRun = 0
			}
			cur.WriteRune(ch)
			spaceRun = 0
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}
