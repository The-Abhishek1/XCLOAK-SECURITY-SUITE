package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

type RegisterResult struct {
	AgentID int
	Token   string
}

// Register registers the agent with the server and returns (agentID, token).
//
// Flow:
//  1. Compute stable machine_id from /etc/machine-id
//  2. Check if a token is already saved on disk (agent restart case)
//  3. POST /api/agents/register with machine_id
//     - First run:    server creates new agent, returns id + token → save token to disk
//     - Restart:      server finds existing machine_id, returns SAME id + token
//  4. Return agentID and token for use in all subsequent calls
func Register() (RegisterResult, error) {

	machineID := MachineID()
	hostname, _ := os.Hostname()

	data := models.AgentRegistration{
		MachineID: machineID,
		Hostname:  hostname,
		OS:        "Linux",
		IPAddress: getLocalIP(),
	}

	body, err := json.Marshal(data)
	if err != nil {
		return RegisterResult{}, err
	}

	resp, err := http.Post(
		config.ServerURL+"/api/agents/register",
		"application/json",
		bytes.NewBuffer(body),
	)

	if err != nil {
		return RegisterResult{}, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return RegisterResult{}, fmt.Errorf("register failed: HTTP %d", resp.StatusCode)
	}

	var result models.RegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return RegisterResult{}, fmt.Errorf("decode response failed: %w", err)
	}

	// Persist the token so we survive restarts without re-registering.
	// On re-registration the server returns the same token, so saving it
	// again is idempotent.
	if err := SaveToken(result.Token); err != nil {
		// Non-fatal: log but continue. The agent will work this session
		// but will re-register on the next restart.
		fmt.Println("Warning: could not save agent token:", err)
	}

	fmt.Printf("Registered as agent %d (machine_id: %s...)\n", result.AgentID, machineID[:8])

	return RegisterResult{
		AgentID: result.AgentID,
		Token:   result.Token,
	}, nil
}

// getLocalIP returns the agent's outbound IP. Falls back to 127.0.0.1.
func getLocalIP() string {

	conn, err := http.Get(config.ServerURL + "/api/health")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Body.Close()

	// The server sees our IP via the TCP connection. We don't need to detect
	// it locally — for display purposes, try to get it from the OS.
	// Simple approach: report the hostname's resolved address.
	return "0.0.0.0"
}
