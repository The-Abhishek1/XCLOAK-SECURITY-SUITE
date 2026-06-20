package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func CreatePlaybook(
	c *gin.Context,
) {

	var playbook models.Playbook

	if err := c.ShouldBindJSON(
		&playbook,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.CreatePlaybook(
		playbook,
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
		gin.H{
			"message": "Playbook Created",
		},
	)
}

func GetPlaybooks(
	c *gin.Context,
) {

	playbooks, err := services.GetPlaybooks(tenantIDFromContext(c))

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
		playbooks,
	)
}
