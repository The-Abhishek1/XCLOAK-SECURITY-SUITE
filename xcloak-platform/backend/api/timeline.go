package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetTenantTimeline returns the most recent events across all agents for the
// caller's tenant — replaces N per-agent requests from the "all agents" view.
func GetTenantTimeline(c *gin.Context) {
	limit := 200
	if l, err := strconv.Atoi(c.Query("limit")); err == nil && l > 0 && l <= 1000 {
		limit = l
	}

	events, err := services.GetTenantTimeline(tenantIDFromContext(c), limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, events)
}

func GetAgentTimeline(
	c *gin.Context,
) {

	id, err := strconv.Atoi(
		c.Param("id"),
	)

	if err != nil {

		c.JSON(
			400,
			gin.H{
				"error": "invalid agent id",
			},
		)

		return
	}

	// Verify the agent belongs to the caller's tenant before building a
	// timeline from its alerts/incidents/playbook executions — those
	// queries below only filter by agent_id, not tenant_id.
	if _, err := repositories.GetAgentByID(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "agent not found"})
		return
	}

	timeline, err := services.GetAgentTimeline(
		id,
	)

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		timeline,
	)
}
