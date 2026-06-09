package agent

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

func Register() (int, error) {

	hostname, _ := os.Hostname()

	data := models.AgentRegistration{
		Hostname:  hostname,
		OS:        "Linux",
		IPAddress: "127.0.0.1",
	}

	body, _ := json.Marshal(data)

	resp, err := http.Post(
		config.ServerURL+"/api/agents/register",
		"application/json",
		bytes.NewBuffer(body),
	)

	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	var result models.RegistrationResponse

	json.NewDecoder(resp.Body).Decode(&result)

	return result.AgentID, nil
}
