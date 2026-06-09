package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

func GetIncidents(c *gin.Context) {

	incidents, err := services.GetIncidents()

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, incidents)
}
