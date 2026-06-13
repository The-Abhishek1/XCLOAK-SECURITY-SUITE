package services

import (
	"crypto/rand"
	"encoding/hex"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// RegisterAgent generates a token for new agents and upserts by machine_id.
// On re-registration the token is NOT regenerated — the DB returns the existing one.
func RegisterAgent(agent models.Agent) (int, string, error) {

	// Generate a token. The repo upserts, so this is only stored on first insert.
	// On conflict (re-registration) the DB ignores this value and returns the stored token.
	token, err := generateToken()
	if err != nil {
		return 0, "", err
	}

	agent.Token = token

	agentID, storedToken, err := repositories.RegisterAgent(agent)
	if err != nil {
		return 0, "", err
	}

	LogEvent("REGISTER_AGENT", agent.Hostname, "system")

	return agentID, storedToken, nil
}

func GetAgentByToken(token string) (*models.Agent, error) {
	return repositories.GetAgentByToken(token)
}

func GetAgents() ([]models.Agent, error) {
	return repositories.GetAgents()
}

func GetAgentByID(id string) (*models.Agent, error) {
	return repositories.GetAgentByID(id)
}

func Heartbeat(agentID int) error {
	return repositories.UpdateAgentHeartbeat(agentID)
}

// generateToken produces a cryptographically random 32-byte hex token (64 chars).
func generateToken() (string, error) {

	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
