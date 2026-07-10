package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

func DashboardOverview(c *gin.Context) {

	overview, err := services.GetDashboardOverview(tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, overview)
}
