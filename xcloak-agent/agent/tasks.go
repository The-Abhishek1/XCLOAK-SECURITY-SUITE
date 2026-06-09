package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

type TaskResponse struct {
	Count int                `json:"count"`
	Tasks []models.AgentTask `json:"tasks"`
}

func FetchTasks(agentID int) ([]models.AgentTask, error) {

	resp, err := http.Get(
		config.ServerURL +
			"/api/tasks/agent/" +
			strconv.Itoa(agentID),
	)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	var result TaskResponse

	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return nil, err
	}

	fmt.Println("Tasks Found:", result.Count)

	return result.Tasks, nil
}
