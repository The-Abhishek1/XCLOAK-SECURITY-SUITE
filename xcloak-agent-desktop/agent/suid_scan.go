//go:build !windows

package agent

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type SUIDBinary struct {
	AgentID  int    `json:"agent_id"`
	FilePath string `json:"file_path"`
	Mode     string `json:"mode"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
}

// suidScanRoots is the filesystem subtree to walk. "/proc" and "/sys" are
// excluded — they contain virtual files with synthetic permissions and would
// produce enormous false-positive counts. "/dev" is also skipped.
var suidScanRoots = []string{"/usr", "/bin", "/sbin", "/opt", "/home"}

// CollectSUIDBinaries walks common filesystem roots and collects any file
// with the SUID (4000) or SGID (2000) bit set. Enterprise SOCs use this
// inventory to detect privilege-escalation vectors and stealthy backdoors.
func CollectSUIDBinaries(agentID int) {
	var binaries []SUIDBinary

	for _, root := range suidScanRoots {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				// Skip known noisy virtual/mount directories
				base := info.Name()
				if base == "proc" || base == "sys" || base == "dev" {
					return filepath.SkipDir
				}
				return nil
			}
			mode := info.Mode()
			if mode&os.ModeSetuid == 0 && mode&os.ModeSetgid == 0 {
				return nil
			}
			entry := SUIDBinary{
				AgentID:  agentID,
				FilePath: path,
				Mode:     mode.String(),
			}
			fimFillStat(&fimFileEntry{}, path) // reuse stat helper indirectly
			fillSUIDStat(&entry, path)
			binaries = append(binaries, entry)
			return nil
		})
	}

	if len(binaries) == 0 {
		slog.Debug("SUID scan found no SUID/SGID binaries")
		return
	}

	body, _ := json.Marshal(binaries)
	resp, err := authPost("/api/agents/suid_binaries", body)
	if err != nil {
		slog.Error("failed sending SUID binaries", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("SUID binaries sent", "count", len(binaries))
}

// excludedPath checks whether a path should be skipped by the SUID scanner.
func excludedPath(path string) bool {
	for _, skip := range []string{"/proc/", "/sys/", "/dev/"} {
		if strings.HasPrefix(path, skip) {
			return true
		}
	}
	return false
}
