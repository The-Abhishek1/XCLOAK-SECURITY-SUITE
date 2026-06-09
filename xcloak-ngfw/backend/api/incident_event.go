package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetIncidentEvents(c *gin.Context) {

	incidentID := c.Param("id")

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
