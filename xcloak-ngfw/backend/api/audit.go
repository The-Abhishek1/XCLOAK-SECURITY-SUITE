package api

import (
	"xcloak-ngfw/repositories"

	"github.com/gin-gonic/gin"
)

func GetAuditLogs(c *gin.Context) {

	logs, err := repositories.GetAuditLogs()

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, logs)
}
