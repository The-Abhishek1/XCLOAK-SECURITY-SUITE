package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetAgentTimeline(
	c *gin.Context,
) {

	id, err := strconv.Atoi(
		c.Param("id"),
	)

	if err != nil {

		c.JSON(
			400,
			gin.H{
				"error": "invalid agent id",
			},
		)

		return
	}

	timeline, err := services.GetAgentTimeline(
		id,
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
		timeline,
	)
}
