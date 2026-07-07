//go:build windows

package agent

import (
	"encoding/csv"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"
)

type CronJob struct {
	AgentID  int    `json:"agent_id"`
	Owner    string `json:"owner"`
	Source   string `json:"source"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
}

// CollectCronJobs collects Windows Scheduled Tasks via schtasks.
func CollectCronJobs(agentID int) {
	out, err := exec.Command("schtasks", "/query", "/fo", "CSV", "/v").Output()
	if err != nil {
		slog.Error("schtasks query failed", "err", err)
		return
	}

	r := csv.NewReader(strings.NewReader(string(out)))
	records, err := r.ReadAll()
	if err != nil || len(records) < 2 {
		slog.Warn("schtasks: no tasks parsed")
		return
	}

	// Build column index
	header := records[0]
	colIdx := make(map[string]int)
	for i, h := range header {
		colIdx[strings.TrimSpace(h)] = i
	}

	get := func(row []string, key string) string {
		i, ok := colIdx[key]
		if !ok || i >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[i])
	}

	var jobs []CronJob
	for _, row := range records[1:] {
		name := get(row, "TaskName")
		if name == "" {
			continue
		}
		jobs = append(jobs, CronJob{
			AgentID:  agentID,
			Owner:    get(row, "Run As User"),
			Source:   "schtasks",
			Schedule: get(row, "Schedule Type") + " " + get(row, "Start Time"),
			Command:  get(row, "Task To Run"),
		})
	}

	if len(jobs) == 0 {
		slog.Debug("no scheduled tasks found")
		return
	}

	body, _ := json.Marshal(jobs)
	resp, err := authPost("/api/agents/cron_jobs", body)
	if err != nil {
		slog.Error("failed sending scheduled tasks", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("scheduled tasks sent", "count", len(jobs))
}
