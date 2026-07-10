//go:build windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
)

type DiskUsage struct {
	AgentID    int     `json:"agent_id"`
	MountPoint string  `json:"mount_point"`
	Device     string  `json:"device"`
	FSType     string  `json:"fs_type"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	FreeGB     float64 `json:"free_gb"`
	UsedPct    float64 `json:"used_pct"`
}

// CollectDiskUsage queries Win32_LogicalDisk via wmic for disk capacity.
func CollectDiskUsage(agentID int) {
	out, err := exec.Command(
		"wmic", "logicaldisk", "get",
		"DeviceID,DriveType,FileSystem,FreeSpace,Size",
		"/FORMAT:CSV",
	).Output()
	if err != nil {
		// Fall back to PowerShell Get-PSDrive
		collectDiskViaPowerShell(agentID)
		return
	}

	var usages []DiskUsage
	lines := strings.Split(string(out), "\n")
	headerFound := false
	var colIdx map[string]int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitCSV(line)
		if !headerFound {
			if strings.EqualFold(fields[0], "Node") || strings.EqualFold(fields[0], "DeviceID") ||
				(len(fields) > 1 && strings.EqualFold(fields[1], "DeviceID")) {
				colIdx = make(map[string]int)
				for i, h := range fields {
					colIdx[strings.ToLower(strings.TrimSpace(h))] = i
				}
				headerFound = true
			}
			continue
		}
		get := func(key string) string {
			i, ok := colIdx[key]
			if !ok || i >= len(fields) {
				return ""
			}
			return strings.TrimSpace(fields[i])
		}
		driveType := get("drivetype")
		// Only report fixed (3) and network (4) drives
		if driveType != "3" && driveType != "4" {
			continue
		}
		sizeStr := get("size")
		freeStr := get("freespace")
		size, _ := strconv.ParseFloat(sizeStr, 64)
		free, _ := strconv.ParseFloat(freeStr, 64)
		used := size - free
		var usedPct float64
		if size > 0 {
			usedPct = (used / size) * 100
		}
		usages = append(usages, DiskUsage{
			AgentID:    agentID,
			MountPoint: get("deviceid"),
			Device:     get("deviceid"),
			FSType:     get("filesystem"),
			TotalGB:    size / 1e9,
			UsedGB:     used / 1e9,
			FreeGB:     free / 1e9,
			UsedPct:    usedPct,
		})
	}

	if len(usages) == 0 {
		slog.Debug("no disks found via wmic")
		return
	}
	sendDiskUsage(agentID, usages)
}

func collectDiskViaPowerShell(agentID int) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | ConvertTo-Json -Compress`,
	).Output()
	if err != nil {
		slog.Error("Get-PSDrive failed", "err", err)
		return
	}
	type psDrive struct {
		Name string  `json:"Name"`
		Used float64 `json:"Used"`
		Free float64 `json:"Free"`
	}
	raw := strings.TrimSpace(string(out))
	var drives []psDrive
	if strings.HasPrefix(raw, "[") {
		json.Unmarshal([]byte(raw), &drives)
	} else {
		var single psDrive
		if err := json.Unmarshal([]byte(raw), &single); err == nil {
			drives = []psDrive{single}
		}
	}
	var usages []DiskUsage
	for _, d := range drives {
		total := d.Used + d.Free
		var usedPct float64
		if total > 0 {
			usedPct = (d.Used / total) * 100
		}
		usages = append(usages, DiskUsage{
			AgentID:    agentID,
			MountPoint: d.Name + ":",
			Device:     d.Name + ":",
			TotalGB:    total / 1e9,
			UsedGB:     d.Used / 1e9,
			FreeGB:     d.Free / 1e9,
			UsedPct:    usedPct,
		})
	}
	sendDiskUsage(agentID, usages)
}

func sendDiskUsage(agentID int, usages []DiskUsage) {
	body, _ := json.Marshal(usages)
	resp, err := authPost("/api/agents/disk_usage", body)
	if err != nil {
		slog.Error("failed sending disk usage", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("disk usage sent", "drives", len(usages))
}
