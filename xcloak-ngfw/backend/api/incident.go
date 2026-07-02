package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
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
