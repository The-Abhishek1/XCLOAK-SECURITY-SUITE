//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"syscall"
)

type DiskUsage struct {
	AgentID    int    `json:"agent_id"`
	MountPoint string `json:"mount_point"`
	Device     string `json:"device"`
	FSType     string `json:"fs_type"`
	TotalGB    float64 `json:"total_gb"`
	UsedGB     float64 `json:"used_gb"`
	FreeGB     float64 `json:"free_gb"`
	UsedPct    float64 `json:"used_pct"`
}

// CollectDiskUsage enumerates mount points from /proc/mounts and calls
// syscall.Statfs to get capacity/usage per filesystem. Virtual and
// pseudo-filesystems (proc, sysfs, devtmpfs, etc.) are filtered out.
func CollectDiskUsage(agentID int) {
	mounts, err := parseMounts()
	if err != nil {
		slog.Error("failed to read /proc/mounts", "err", err)
		return
	}

	skipFS := map[string]bool{
		"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true,
		"tmpfs": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"securityfs": true, "debugfs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "tracefs": true, "bpf": true, "ramfs": true,
		"squashfs": true, // snap loop mounts — large count, low value for SOC
	}

	var usages []DiskUsage
	seen := make(map[string]bool)
	for _, m := range mounts {
		if skipFS[m.fsType] {
			continue
		}
		if seen[m.mountPoint] {
			continue
		}
		seen[m.mountPoint] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(m.mountPoint, &stat); err != nil {
			continue
		}
		total := float64(stat.Blocks) * float64(stat.Bsize)
		free := float64(stat.Bfree) * float64(stat.Bsize)
		used := total - free
		var usedPct float64
		if total > 0 {
			usedPct = (used / total) * 100
		}
		usages = append(usages, DiskUsage{
			AgentID:    agentID,
			MountPoint: m.mountPoint,
			Device:     m.device,
			FSType:     m.fsType,
			TotalGB:    total / 1e9,
			UsedGB:     used / 1e9,
			FreeGB:     free / 1e9,
			UsedPct:    usedPct,
		})
	}

	if len(usages) == 0 {
		slog.Debug("no disk mounts to report")
		return
	}

	body, _ := json.Marshal(usages)
	resp, err := authPost("/api/agents/disk_usage", body)
	if err != nil {
		slog.Error("failed sending disk usage", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("disk usage sent", "mounts", len(usages))
}

type mountEntry struct {
	device     string
	mountPoint string
	fsType     string
}

func parseMounts() ([]mountEntry, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []mountEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		entries = append(entries, mountEntry{
			device:     fields[0],
			mountPoint: fields[1],
			fsType:     fields[2],
		})
	}
	return entries, nil
}
