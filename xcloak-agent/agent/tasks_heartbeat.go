package agent

import (
	"encoding/json"
	"fmt"
	"strconv"

	"xcloak-agent/models"
)

// SendHeartbeat pings the server using the authenticated client.
func SendHeartbeat(client *AuthClient) {

	resp, err := client.Post("/api/agents/heartbeat", map[string]string{})

	if err != nil {
		fmt.Println("Heartbeat failed:", err)
		return
	}

	defer resp.Body.Close()
}

type TaskResponse struct {
	Count int                `json:"count"`
	Tasks []models.AgentTask `json:"tasks"`
}

// FetchTasks polls for pending tasks assigned to this agent.
// Agent ID is included in the URL but auth is enforced server-side by token —
// the server will only return tasks for the agent matching the token.
func FetchTasks(client *AuthClient, agentID int) ([]models.AgentTask, error) {

	resp, err := client.Get("/api/tasks/agent/" + strconv.Itoa(agentID))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result TaskResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	fmt.Println("Tasks found:", result.Count)

	return result.Tasks, nil
}
