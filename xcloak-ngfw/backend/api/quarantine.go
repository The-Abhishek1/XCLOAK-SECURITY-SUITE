package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func ReceiveQuarantinedFile(c *gin.Context) {

	var file models.QuarantinedFile

	if err := c.ShouldBindJSON(&file); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.SaveQuarantinedFile(
		file,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Quarantine Recorded",
	})
}

func GetQuarantinedFiles(c *gin.Context) {

	files, err := services.GetQuarantinedFiles(tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, files)
}
