//go:build windows

package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"xcloak-agent-desktop/models"
)

// readNewLines reads up to maxLines lines from the current position of f.
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
			break
		}
	}

	return lines, totalBytes
}

// sendLogLines packages raw log strings into models.Log and POSTs to server.
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

// fileInode on Windows returns 0 — Windows doesn't expose inodes the same
// way. Log rotation detection is handled by file size comparison instead
// (the collectAuthLogsTail logic will reset on size shrink).
func fileInode(fi os.FileInfo) uint64 {
	return 0
}

// trimNewline strips trailing \n and \r.
func trimNewline(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
