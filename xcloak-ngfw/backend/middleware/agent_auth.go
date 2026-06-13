package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

const AgentKey = "agent"

// RequireAgentAuth validates the agent's bearer token and injects the resolved
// agent into the context. Attach to all agent-facing endpoints except /register.
//
// The agent sends:  Authorization: Bearer <token>
func RequireAgentAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		header := c.GetHeader("Authorization")

		if header == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "missing Authorization header"})
			return
		}

		parts := strings.SplitN(header, " ", 2)

		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid Authorization format"})
			return
		}

		token := strings.TrimSpace(parts[1])

		if token == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "empty token"})
			return
		}

		agent, err := services.GetAgentByToken(token)

		if err != nil {
			// Token not found — reject. Don't leak whether it exists.
			c.AbortWithStatusJSON(401, gin.H{"error": "invalid agent token"})
			return
		}

		// Inject agent into context so handlers can read agent.ID directly
		// without trusting the agent_id field in the request body.
		c.Set(AgentKey, agent)
		c.Next()
	}
}
