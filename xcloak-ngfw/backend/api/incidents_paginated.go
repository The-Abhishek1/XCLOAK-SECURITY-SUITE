package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
)

// GetIncidentsPaginated — GET /api/incidents/paginated
// Query: page, per_page, status
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
