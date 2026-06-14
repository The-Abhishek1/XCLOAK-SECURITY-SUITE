package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateAgentJWT issues a long-lived token for an agent (90 days).
// The token carries role="agent" and the agent's numeric ID so the
// RequireAgentAuth middleware can identify which agent is calling.
func GenerateAgentJWT(agentID int) (string, error) {

	claims := jwt.MapClaims{
		"agent_id": agentID,
		"role":     "agent",
		"exp":      time.Now().Add(90 * 24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(JwtSecret)
}
