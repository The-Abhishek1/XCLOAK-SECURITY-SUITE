package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

const maxAgentLogBytes = 10 << 20 // 10 MiB per batch — matches /api/ingest limit

func ReceiveLogs(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAgentLogBytes)

	logs := []models.Log{}

	if err := c.ShouldBindJSON(&logs); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.SaveLogs(logs)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Logs Received",
	})
}
