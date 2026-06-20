package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetAlerts(c *gin.Context) {

	alerts, err := services.GetAlerts(tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, alerts)
}
