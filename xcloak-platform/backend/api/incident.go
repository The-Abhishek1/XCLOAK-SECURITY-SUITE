package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/services"
)

// GetIncidents returns open and recently closed incidents for the tenant.
//
// @Summary      List incidents
// @Tags         incidents
// @Produce      json
// @Success      200  {array}   models.Incident
// @Failure      500  {object}  map[string]string
// @Security     BearerAuth
// @Router       /api/incidents [get]
func GetIncidents(c *gin.Context) {

	incidents, err := services.GetIncidents(tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, incidents)
}

// GetIncidentStatusCounts — GET /api/incidents/counts
// Returns per-status incident counts for the tenant in a single GROUP BY query.
// Used by the frontend tab badges to avoid loading all incidents just to count them.
func GetIncidentStatusCounts(c *gin.Context) {
	rows, err := database.DB.Query(`
		SELECT status, COUNT(*) FROM incidents
		WHERE tenant_id = $1
		GROUP BY status
	`, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	counts := map[string]int{"open": 0, "investigating": 0, "resolved": 0, "closed": 0}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err == nil {
			counts[status] = n
		}
	}
	c.JSON(200, counts)
}
