package agent

import (
	"bytes"
	"encoding/json"
	"net/http"

	"xcloak-agent/config"
)

func SendHeartbeat(agentID int) {

	data := map[string]int{
		"agent_id": agentID,
	}

	body, _ := json.Marshal(data)

	http.Post(
		config.ServerURL+"/api/agents/heartbeat",
		"application/json",
		bytes.NewBuffer(body),
	)
}
