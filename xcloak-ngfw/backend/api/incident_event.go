package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

func GetIncidentEvents(c *gin.Context) {

	incidentID := c.Param("id")

	// Verify the incident belongs to the caller's tenant before returning
	// its timeline — incident_events itself isn't tenant-filtered, so this
	// is the only check standing between a guessed ID and another tenant's
	// data.
	if _, err := repositories.GetIncidentByID(incidentID, tenantIDFromContext(c)); err != nil {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}

	events, err := services.GetIncidentEvents(
		incidentID,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, events)
}
