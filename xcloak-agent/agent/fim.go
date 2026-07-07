package agent

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// DefaultWatchPaths is the default list of paths monitored for FIM.
var DefaultWatchPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
	"/etc/crontab",
	"/etc/hosts",
	"/etc/hostname",
	"/etc/resolv.conf",
	"/etc/ld.so.conf",
	"/etc/ld.so.preload",
	"/etc/pam.d",
	"/usr/bin/sudo",
	"/usr/bin/passwd",
	"/usr/bin/su",
	"/bin/bash",
	"/bin/sh",
	"/usr/sbin/sshd",
	"/usr/lib/systemd/system",
	"/etc/systemd/system",
}

// fimFileEntry matches the server's FIMFileEntry JSON shape.
// Mode, Owner, and Group enable permission/ownership change detection
// in addition to hash-based integrity checks.
type fimFileEntry struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256_hash"`
	FileSize int64  `json:"file_size"`
	Mode     string `json:"mode,omitempty"`    // e.g. "-rwsr-xr-x"
	UID      int    `json:"uid,omitempty"`
	GID      int    `json:"gid,omitempty"`
	ModTime  string `json:"mod_time,omitempty"` // RFC3339
}

type fimScanPayload struct {
	AgentID int            `json:"agent_id"`
	Files   []fimFileEntry `json:"files"`
}

type fimTaskPayload struct {
	WatchPaths []string `json:"watch_paths"`
}

// RunFIMScan hashes all watched files and submits results to the server.
func RunFIMScan(agentID int, taskPayload []byte) {
	var taskPL fimTaskPayload
	if err := json.Unmarshal(taskPayload, &taskPL); err != nil {
		slog.Debug("FIM: using default watch paths", "err", err)
	}

	paths := DefaultWatchPaths
	if len(taskPL.WatchPaths) > 0 {
		paths = taskPL.WatchPaths
	}

	var files []fimFileEntry
	for _, path := range paths {
		entries, err := fimScanPath(path)
		if err != nil {
			slog.Debug("FIM: skipping path", "path", path, "err", err)
			continue
		}
		files = append(files, entries...)
	}

	payload := fimScanPayload{AgentID: agentID, Files: files}
	body, _ := json.Marshal(payload)

	resp, err := authPost("/api/agents/fim", body)
	if err != nil {
		slog.Error("FIM: failed to submit scan", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("FIM scan submitted", "files", len(files))
}

// fimScanPath returns fimFileEntry records for a file or directory tree.
func fimScanPath(path string) ([]fimFileEntry, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		entry, err := fimHashFile(path, info)
		if err != nil {
			return nil, err
		}
		return []fimFileEntry{entry}, nil
	}

	var entries []fimFileEntry
	filepath.Walk(path, func(fp string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if fi.Size() > 100*1024*1024 {
			return nil
		}
		entry, err := fimHashFile(fp, fi)
		if err == nil {
			entries = append(entries, entry)
		}
		return nil
	})
	return entries, nil
}

// fimHashFile builds a fimFileEntry including hash + permissions + ownership.
func fimHashFile(path string, info os.FileInfo) (fimFileEntry, error) {
	hash, err := hashFile(path)
	if err != nil {
		return fimFileEntry{}, err
	}

	entry := fimFileEntry{
		FilePath: path,
		SHA256:   hash.SHA256Hash,
		FileSize: info.Size(),
		Mode:     info.Mode().String(),
		ModTime:  fmt.Sprintf("%s", info.ModTime().UTC().Format("2006-01-02T15:04:05Z")),
	}
	fimFillStat(&entry, path)
	return entry, nil
}
