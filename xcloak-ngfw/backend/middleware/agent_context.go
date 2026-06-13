package middleware

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
)

// AgentFromContext returns the authenticated agent injected by RequireAgentAuth.
// Call this in any handler protected by RequireAgentAuth — agent is guaranteed non-nil.
func AgentFromContext(c *gin.Context) *models.Agent {
	agent, _ := c.Get(AgentKey)
	return agent.(*models.Agent)
}
