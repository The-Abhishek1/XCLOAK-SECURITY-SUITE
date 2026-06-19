//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"

	"xcloak-agent/models"
)

// readNewLines reads up to maxLines lines from the current position of f.
// Returns the lines read and the exact number of bytes consumed so the caller
// can advance the stored file offset correctly.
func readNewLines(f *os.File, maxLines int) ([]string, int64) {
	var lines []string
	var totalBytes int64

	reader := bufio.NewReader(f)

	for len(lines) < maxLines {
		line, err := reader.ReadString('\n')
		totalBytes += int64(len(line))

		trimmed := trimNewline(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("[collector] readNewLines error: %v\n", err)
			break
		}
	}

	return lines, totalBytes
}

// sendLogLines packages a slice of raw log strings into models.Log and POSTs
// them to the server in one request.
func sendLogLines(agentID int, source string, lines []string) error {
	logs := make([]models.Log, 0, len(lines))
	for _, l := range lines {
		logs = append(logs, models.Log{
			AgentID:    agentID,
			LogSource:  source,
			LogMessage: l,
		})
	}

	body, err := json.Marshal(logs)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	resp, err := authPost("/api/agents/logs", body)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return nil
}

// fileInode extracts the inode number from a FileInfo on Linux/macOS.
// Used to detect log rotation (a new file with a different inode replaces
// the old one at the same path).
func fileInode(fi os.FileInfo) uint64 {
	if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

// trimNewline strips trailing \n and \r from a string.
func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
