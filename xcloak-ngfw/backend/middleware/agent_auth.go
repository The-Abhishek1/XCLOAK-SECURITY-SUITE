package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// AgentKey is the gin context key for the authenticated agent.
const AgentKey = "authenticated_agent"

// RequireAgentAuth validates an agent bearer token by looking it up in the
// database via services.GetAgentByToken. This matches the backend's token
// design: agents receive a random hex token on registration which is stored
// in the agents table and validated here on every request.
func RequireAgentAuth() gin.HandlerFunc {

	return func(c *gin.Context) {

		header := c.GetHeader("Authorization")

		if header == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing agent token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "empty agent token"})
			c.Abort()
			return
		}

		agent, err := services.GetAgentByToken(tokenString)
		if err != nil || agent == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid agent token"})
			c.Abort()
			return
		}

		c.Set(AgentKey, agent)
		c.Set("agent_id", agent.ID)
		c.Next()
	}
}
