package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

type registrationResponse struct {
	AgentID int    `json:"agent_id"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

func Register() (int, error) {

	hostname, _ := os.Hostname()

	// Derive a stable machine_id from the hostname so re-registration
	// hits the ON CONFLICT (machine_id) path and returns the same agent_id.
	machineID := deriveMachineID(hostname)

	data := models.AgentRegistration{
		MachineID: machineID,
		Hostname:  hostname,
		OS:        "Linux",
		IPAddress: getLocalIP(),
	}

	body, _ := json.Marshal(data)

	resp, err := http.Post(
		config.ServerURL+"/api/agents/register",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return 0, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("register returned HTTP %d", resp.StatusCode)
	}

	var result registrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode register response: %w", err)
	}

	if result.AgentID == 0 {
		return 0, fmt.Errorf("server returned agent_id=0")
	}

	// Save token for all subsequent authPost() calls.
	if result.Token != "" {
		SaveToken(result.Token)
		fmt.Println("Agent token saved")
	} else {
		fmt.Println("Warning: server did not return a token")
	}

	fmt.Printf("Registered as agent %d (machine_id: %s...)\n",
		result.AgentID, machineID[:12])

	return result.AgentID, nil
}

// deriveMachineID creates a stable 64-char hex fingerprint from the hostname.
// Using sha256 means it's deterministic across restarts without needing
// /etc/machine-id or any privileged file access.
func deriveMachineID(hostname string) string {
	h := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(h[:])
}

// getLocalIP tries to read the primary outbound IP; falls back to 127.0.0.1.
func getLocalIP() string {
	// Simple approach: use hostname resolution.
	// For a more accurate IP, you'd dial a UDP connection to 8.8.8.8:80
	// and read the local address — but that requires network access at startup.
	return "127.0.0.1"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
