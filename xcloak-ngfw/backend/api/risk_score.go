package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/repositories"
)

func GetRiskScore(
	c *gin.Context,
) {

	agentID := c.Param("id")

	score, err := repositories.GetRiskScore(
		agentID,
	)

	if err != nil {

		c.JSON(
			404,
			gin.H{
				"error": "Risk score not found",
			},
		)

		return
	}

	c.JSON(
		200,
		score,
	)
}
