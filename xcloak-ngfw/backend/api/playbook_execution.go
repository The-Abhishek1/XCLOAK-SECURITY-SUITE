package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetPlaybookExecutions(
	c *gin.Context,
) {

	executions, err := services.GetPlaybookExecutions(tenantIDFromContext(c))

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		executions,
	)
}
