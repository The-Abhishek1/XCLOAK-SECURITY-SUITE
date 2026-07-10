package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

// GetSOCMetrics — GET /api/soc/metrics
func GetSOCMetrics(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	m, err := services.GetSOCMetrics(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, m)
}

// GetVulnPriorityQueue — GET /api/vulns/priority-queue
func GetVulnPriorityQueue(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	patchStatus := c.DefaultQuery("status", "open,in_progress")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	items, err := services.QueryVulnPriorityQueue(tenantID, patchStatus, limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if items == nil {
		items = []services.VulnQueueItem{}
	}
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

// UpdateVulnPatchStatus — PATCH /api/vulns/:id/patch-status
func UpdateVulnPatchStatus(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		Status string `json:"status"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if err := services.UpdateVulnPatchStatus(id, tenantID, body.Status, body.Notes); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// RefreshVulnPriorities — POST /api/vulns/refresh-priorities
func RefreshVulnPriorities(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	go services.RefreshVulnPriorityScores(tenantID)
	c.JSON(http.StatusOK, gin.H{"message": "priority refresh started"})
}

// GetAlertInvestigation — GET /api/alerts/:id/investigate
func GetAlertInvestigation(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	ctx, err := services.BuildInvestigationContext(id, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, ctx)
}
