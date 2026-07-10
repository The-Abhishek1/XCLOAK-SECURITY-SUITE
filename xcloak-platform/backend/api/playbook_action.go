package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
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
		tenantIDFromContext(c),
	)

	if err != nil {

		status := 500
		if err == services.ErrPlaybookNotFoundForAction {
			status = 404
		}

		c.JSON(
			status,
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
		tenantIDFromContext(c),
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
		tenantIDFromContext(c),
	)

	if err != nil {

		status := 500
		if err == repositories.ErrPlaybookActionNotFound {
			status = 404
		}

		c.JSON(
			status,
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
