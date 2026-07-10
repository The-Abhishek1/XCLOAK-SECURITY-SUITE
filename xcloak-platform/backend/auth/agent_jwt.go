package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateAgentJWT issues a long-lived token for an agent (90 days).
// Uses the same JWT_SECRET as user tokens but with role="agent".
func GenerateAgentJWT(agentID int) (string, error) {
	claims := jwt.MapClaims{
		"agent_id": agentID,
		"role":     "agent",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(90 * 24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret())
}
