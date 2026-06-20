package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func TestRules(
	c *gin.Context,
) {

	var req models.RuleTestRequest

	if err := c.ShouldBindJSON(
		&req,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	results := services.TestRules(
		req.Message,
		tenantIDFromContext(c),
	)

	c.JSON(
		200,
		results,
	)
}
