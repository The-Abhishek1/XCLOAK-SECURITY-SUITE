package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func CreateThreatFeed(
	c *gin.Context,
) {

	var feed models.ThreatFeed

	if err := c.ShouldBindJSON(
		&feed,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.CreateThreatFeed(
		feed,
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
			"message": "Feed Created",
		},
	)
}

func GetThreatFeeds(
	c *gin.Context,
) {

	feeds, err := services.GetThreatFeeds()

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
		feeds,
	)
}
