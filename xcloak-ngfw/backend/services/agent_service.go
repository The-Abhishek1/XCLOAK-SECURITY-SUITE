package services

import (
	"crypto/rand"
	"encoding/hex"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// RegisterAgent generates a token for new agents and upserts by machine_id,
// scoped to tenantID (the tenant that owns the install token used).
// On re-registration the token is NOT regenerated — the DB returns the existing one.
func RegisterAgent(agent models.Agent, tenantID int) (int, string, error) {

	// Generate a token. The repo upserts, so this is only stored on first insert.
	// On conflict (re-registration) the DB ignores this value and returns the stored token.
	token, err := generateToken()
	if err != nil {
		return 0, "", err
	}

	agent.Token = token

	agentID, storedToken, err := repositories.RegisterAgent(agent, tenantID)
	if err != nil {
		return 0, "", err
	}

	// Classify immediately so platform_category is set before the first query.
	UpdateAgentPlatform(agentID, agent.OS)

	LogEvent("REGISTER_AGENT", agent.Hostname, "system")

	return agentID, storedToken, nil
}

func GetAgentByToken(token string) (*models.Agent, error) {
	return repositories.GetAgentByToken(token)
}

func GetAgents(tenantID int) ([]models.Agent, error) {
	return repositories.GetAgents(tenantID)
}

// GetAllAgents returns every agent across every tenant — for internal
// background jobs only, see repositories.GetAllAgents.
func GetAllAgents() ([]models.Agent, error) {
	return repositories.GetAllAgents()
}

func GetAgentByID(id string, tenantID int) (*models.Agent, error) {
	return repositories.GetAgentByID(id, tenantID)
}

func Heartbeat(req models.HeartbeatRequest) error {
	if err := repositories.UpdateAgentHeartbeat(req.AgentID, req.Version, req.UptimeSeconds, req.MemAllocMB, req.Goroutines); err != nil {
		return err
	}
	// Re-classify if this agent's category is still 'other'. This catches
	// agents whose OS string was empty at registration time.
	if req.AgentID > 0 {
		var os, cat string
		database.DB.QueryRow(
			`SELECT COALESCE(os,''), platform_category FROM agents WHERE id=$1`,
			req.AgentID,
		).Scan(&os, &cat)
		if cat == "other" && os != "" {
			UpdateAgentPlatform(req.AgentID, os)
		}
	}
	return nil
}

// generateToken produces a cryptographically random 32-byte hex token (64 chars).
func generateToken() (string, error) {

	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}
