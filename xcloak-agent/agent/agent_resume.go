package agent

import (
	"encoding/json"
	"fmt"
	"net/http"

	"xcloak-agent/config"
)

// ResumeSession uses the saved token to look up the current agent's ID.
// Called on startup when a token file already exists.
func ResumeSession() (int, error) {
	token := LoadToken()
	if token == "" {
		return 0, fmt.Errorf("no saved token")
	}

	req, err := http.NewRequest("GET", config.ServerURL+"/api/agents/me", nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return 0, fmt.Errorf("token revoked or expired")
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var body struct {
		AgentID int `json:"agent_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return 0, err
	}
	if body.AgentID == 0 {
		return 0, fmt.Errorf("server returned agent_id=0")
	}

	return body.AgentID, nil
}
