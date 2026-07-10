package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetAgentTaskHistory — GET /api/agents/:id/tasks
func GetAgentTaskHistory(c *gin.Context) {
	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}
	tasks, err := repositories.GetAgentTaskHistory(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if tasks == nil {
		tasks = []models.AgentTask{}
	}
	c.JSON(200, tasks)
}

// GetComplianceFrameworkScores — GET /api/compliance/reports/:id/scores
func GetComplianceFrameworkScores(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid report id"})
		return
	}

	tenantID := tenantIDFromContext(c)

	// Verify the report belongs to the caller's tenant before computing or
	// returning scores for it — report_id alone isn't tenant-checked below.
	if _, err := services.GetReportByID(c.Param("id"), tenantID); err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}

	scores, err := services.GetFrameworkScores(id, tenantID)
	if err != nil || len(scores) == 0 {
		// Compute on-demand if not yet stored.
		scores, _ = services.ComputeAllFrameworkScores(id, tenantID)
	}
	if scores == nil {
		scores = []services.FrameworkScore{}
	}
	c.JSON(200, scores)
}
