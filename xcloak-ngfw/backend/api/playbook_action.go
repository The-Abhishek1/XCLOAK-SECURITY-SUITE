package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func CreatePlaybookAction(
	c *gin.Context,
) {

	var action models.PlaybookAction

	if err := c.ShouldBindJSON(
		&action,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.CreatePlaybookAction(
		action,
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
			"message": "Action Created",
		},
	)
}

func GetPlaybookActions(
	c *gin.Context,
) {

	playbookID := c.Param("id")

	actions, err := services.GetPlaybookActions(
		playbookID,
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
		actions,
	)
}

func DeletePlaybookAction(
	c *gin.Context,
) {

	id := c.Param("id")

	err := services.DeletePlaybookAction(
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
		gin.H{
			"message": "Action Deleted",
		},
	)
}
