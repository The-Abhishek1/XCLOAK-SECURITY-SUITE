//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type CronJob struct {
	AgentID  int    `json:"agent_id"`
	Owner    string `json:"owner"`    // "root", username, or filename
	Source   string `json:"source"`   // /etc/crontab, /etc/cron.d/foo, crontab:username
	Schedule string `json:"schedule"` // "*/5 * * * *"
	Command  string `json:"command"`
}

// CollectCronJobs collects all scheduled tasks from:
//   - /etc/crontab
//   - /etc/cron.d/*
//   - /var/spool/cron/crontabs/* (per-user crontabs)
func CollectCronJobs(agentID int) {
	var jobs []CronJob

	jobs = append(jobs, parseCronFile(agentID, "/etc/crontab", "root", "/etc/crontab")...)

	if entries, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		for _, path := range entries {
			jobs = append(jobs, parseCronFile(agentID, path, "root", path)...)
		}
	}

	for _, dir := range []string{"/var/spool/cron/crontabs", "/var/spool/cron"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			path := filepath.Join(dir, e.Name())
			jobs = append(jobs, parseCronFile(agentID, path, e.Name(), "crontab:"+e.Name())...)
		}
	}

	if len(jobs) == 0 {
		slog.Debug("no cron jobs found")
		return
	}

	body, _ := json.Marshal(jobs)
	resp, err := authPost("/api/agents/cron_jobs", body)
	if err != nil {
		slog.Error("failed sending cron jobs", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("cron jobs sent", "count", len(jobs))
}

func parseCronFile(agentID int, path, owner, source string) []CronJob {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var jobs []CronJob
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip environment variable assignments
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "@") {
			parts := strings.SplitN(line, "=", 2)
			if !strings.ContainsAny(parts[0], " \t") {
				continue
			}
		}
		// @reboot / @hourly / @daily / etc.
		if strings.HasPrefix(line, "@") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				jobs = append(jobs, CronJob{
					AgentID:  agentID,
					Owner:    owner,
					Source:   source,
					Schedule: parts[0],
					Command:  strings.Join(parts[1:], " "),
				})
			}
			continue
		}
		// Standard 5-field (user crontab) or 6-field (/etc/crontab with user column)
		fields := strings.Fields(line)
		if len(fields) >= 6 {
			schedule := strings.Join(fields[:5], " ")
			cmd := strings.Join(fields[5:], " ")
			// /etc/crontab has 6 fields before command: min hr dom mon dow user cmd
			if len(fields) >= 7 && (source == "/etc/crontab" || strings.HasPrefix(source, "/etc/cron.d/")) {
				schedule = strings.Join(fields[:5], " ")
				owner = fields[5]
				cmd = strings.Join(fields[6:], " ")
			}
			jobs = append(jobs, CronJob{
				AgentID:  agentID,
				Owner:    owner,
				Source:   source,
				Schedule: schedule,
				Command:  cmd,
			})
		}
	}
	return jobs
}
