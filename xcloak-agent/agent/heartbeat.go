package agent

import (
	"encoding/json"
	"fmt"
)

// SendHeartbeat pings the server to keep the agent marked online.
// Uses authPost so the heartbeat endpoint can require agent auth.
func SendHeartbeat(agentID int) {

	data := map[string]int{"agent_id": agentID}
	body, _ := json.Marshal(data)

	resp, err := authPost("/api/agents/heartbeat", body)
	if err != nil {
		fmt.Println("Heartbeat failed:", err)
		return
	}
	defer resp.Body.Close()
}
