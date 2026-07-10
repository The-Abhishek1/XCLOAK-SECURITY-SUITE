package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
)

func GetAuditLogs(c *gin.Context) {
	logs, err := repositories.GetAuditLogs(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, logs)
}

// GetAuditLogsPaginatedHandler — GET /api/audit/logs/paginated
// Query params: page, per_page, q (search action/details/username), from, to (ISO dates)
func GetAuditLogsPaginatedHandler(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	q := c.Query("q")
	from := c.Query("from")
	to := c.Query("to")

	result, err := repositories.GetAuditLogsFiltered(tenantIDFromContext(c), page, perPage, q, from, to)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

// GetAuditExportStatusHandler — GET /api/audit/export/status
// Shows how far the immutable export to MinIO has progressed.
func GetAuditExportStatusHandler(c *gin.Context) {
	lastID, lastAt, lastKey, err := repositories.GetAuditExportStatus()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"last_exported_id": lastID,
		"last_exported_at": lastAt,
		"last_object_key":  lastKey,
	})
}
