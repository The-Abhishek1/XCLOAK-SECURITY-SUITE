package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func ReceiveYaraMatches(
	c *gin.Context,
) {

	var matches []models.YaraMatch

	if err := c.ShouldBindJSON(
		&matches,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.SaveYaraMatches(
		matches,
	)

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
		gin.H{
			"message": "YARA Matches Saved",
		},
	)
}
