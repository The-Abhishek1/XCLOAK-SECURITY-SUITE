package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// GetAlerts returns all alerts for the authenticated tenant.
//
// @Summary      List alerts
// @Tags         alerts
// @Produce      json
// @Success      200  {array}   models.Alert
// @Failure      500  {object}  map[string]string
// @Security     BearerAuth
// @Router       /api/alerts [get]
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
