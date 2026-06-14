package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
)

// GetAlertsPaginated — GET /api/alerts/paginated
// Query params: page, per_page, severity, agent_id
func GetAlertsPaginated(c *gin.Context) {

	page, _    := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	severity   := c.Query("severity")
	agentID    := c.Query("agent_id")

	result, err := repositories.GetAlertsPaginated(page, perPage, severity, agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}

// GetIncidentsPaginated — GET /api/incidents/paginated
// Query params: page, per_page, status
func GetIncidentsPaginated(c *gin.Context) {

	page, _    := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "25"))
	status     := c.Query("status")

	result, err := repositories.GetIncidentsPaginated(page, perPage, status)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}

// GetAuditLogsPaginated — GET /api/audit/logs/paginated
// Query params: page, per_page, action
func GetAuditLogsPaginated(c *gin.Context) {

	page, _    := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	action     := c.Query("action")

	result, err := repositories.GetAuditLogsPaginated(page, perPage, action)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}
