package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
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

func GetPlaybookByID(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid id"})
		return
	}
	p, err := repositories.GetPlaybookByID(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, p)
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
