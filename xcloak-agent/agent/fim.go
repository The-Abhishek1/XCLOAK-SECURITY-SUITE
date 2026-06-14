package agent

import (
	"encoding/json"
	"fmt"
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
	"/usr/bin/sudo",
	"/usr/bin/passwd",
	"/usr/bin/su",
	"/bin/bash",
	"/bin/sh",
	"/usr/sbin/sshd",
}

// fimFileEntry matches the server's FIMFileEntry JSON shape.
type fimFileEntry struct {
	FilePath string `json:"file_path"`
	SHA256   string `json:"sha256_hash"`
	FileSize int64  `json:"file_size"`
}

type fimScanPayload struct {
	AgentID int            `json:"agent_id"`
	Files   []fimFileEntry `json:"files"`
}

type fimTaskPayload struct {
	WatchPaths []string `json:"watch_paths"`
}

// RunFIMScan hashes all watched files and submits results to the server.
// The server compares against the stored baseline and raises alerts on changes.
func RunFIMScan(agentID int, taskPayload []byte) {

	var taskPL fimTaskPayload
	json.Unmarshal(taskPayload, &taskPL)

	paths := DefaultWatchPaths
	if len(taskPL.WatchPaths) > 0 {
		paths = taskPL.WatchPaths
	}

	var files []fimFileEntry

	for _, path := range paths {
		entries, err := fimScanPath(path)
		if err != nil {
			fmt.Printf("FIM: skipping %s: %v\n", path, err)
			continue
		}
		files = append(files, entries...)
	}

	payload := fimScanPayload{AgentID: agentID, Files: files}
	body, _ := json.Marshal(payload)

	resp, err := authPost("/api/agents/fim", body)
	if err != nil {
		fmt.Println("FIM: failed to submit scan:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("FIM scan submitted: %d files\n", len(files))
}

// fimScanPath returns fimFileEntry records for a file or directory tree.
// It reuses the existing hashFile() from file_hashes.go (returns HashResult).
func fimScanPath(path string) ([]fimFileEntry, error) {

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		entry, err := fimHashFile(path)
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
		entry, err := fimHashFile(fp)
		if err == nil {
			entries = append(entries, entry)
		}
		return nil
	})

	return entries, nil
}

// fimHashFile wraps the existing hashFile() from file_hashes.go.
// We only need SHA256 for FIM (not MD5), and we also need file size.
func fimHashFile(path string) (fimFileEntry, error) {

	// hashFile is defined in file_hashes.go — returns (HashResult, error).
	hash, err := hashFile(path)
	if err != nil {
		return fimFileEntry{}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return fimFileEntry{}, err
	}

	return fimFileEntry{
		FilePath: path,
		SHA256:   hash.SHA256Hash,
		FileSize: info.Size(),
	}, nil
}
