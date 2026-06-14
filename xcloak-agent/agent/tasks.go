package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

type TaskResponse struct {
	Count int                `json:"count"`
	Tasks []models.AgentTask `json:"tasks"`
}

// FetchTasks polls the server for pending tasks for this agent. Uses the
// agent's saved bearer token (RequireAgentAuth). On transient network errors
// it retries up to maxRetries times with exponential backoff — so a brief
// server restart doesn't permanently stop task delivery.
func FetchTasks(agentID int) ([]models.AgentTask, error) {

	const maxRetries = 3
	const baseDelay  = 2 * time.Second

	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {

		if attempt > 0 {
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			fmt.Printf("FetchTasks: retry %d/%d in %s\n", attempt, maxRetries, delay)
			time.Sleep(delay)
		}

		tasks, err := doFetchTasks(agentID)
		if err == nil {
			return tasks, nil
		}

		lastErr = err
		fmt.Println("FetchTasks: transient error:", err)
	}

	return nil, lastErr
}

func doFetchTasks(agentID int) ([]models.AgentTask, error) {

	req, err := http.NewRequest(
		"GET",
		config.ServerURL+"/api/tasks/agent/"+strconv.Itoa(agentID),
		nil,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+LoadToken())

	resp, err := http.DefaultClient.Do(req)
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

	fmt.Println("Tasks found:", result.Count)

	return result.Tasks, nil
}
