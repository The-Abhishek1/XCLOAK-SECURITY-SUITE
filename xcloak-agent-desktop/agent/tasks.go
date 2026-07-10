package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"xcloak-agent-desktop/config"
	"xcloak-agent-desktop/models"
)

type TaskResponse struct {
	Count int                `json:"count"`
	Tasks []models.AgentTask `json:"tasks"`
}

// FetchTasks polls the server for pending tasks for this agent. Retries up to
// maxRetries times with exponential backoff on transient network errors.
func FetchTasks(agentID int) ([]models.AgentTask, error) {

	const maxRetries = 3
	const baseDelay  = 2 * time.Second

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			slog.Debug("FetchTasks retry", "attempt", attempt, "max", maxRetries, "delay", delay)
			time.Sleep(delay)
		}
		tasks, err := doFetchTasks(agentID)
		if err == nil {
			return tasks, nil
		}
		lastErr = err
		slog.Warn("FetchTasks transient error", "attempt", attempt+1, "err", err)
	}

	return nil, lastErr
}

func doFetchTasks(agentID int) ([]models.AgentTask, error) {

	req, err := http.NewRequest(
		"GET",
		config.ServerURL()+"/api/tasks/agent/"+strconv.Itoa(agentID),
		nil,
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+LoadToken())

	resp, err := Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("agent not authorized (401) — check token")
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d from task poll", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result TaskResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	if result.Count > 0 {
		slog.Info("tasks received", "count", result.Count)
	}
	return result.Tasks, nil
}
