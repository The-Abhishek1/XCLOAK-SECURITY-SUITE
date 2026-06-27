package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func GetPlaybookExecutions(c *gin.Context) {
	executions, err := services.GetPlaybookExecutions(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if executions == nil {
		executions = []models.PlaybookExecution{}
	}
	c.JSON(200, executions)
}

func GetPlaybookStepResults(c *gin.Context) {
	executionID := c.Param("id")
	results, err := services.GetPlaybookStepResults(executionID, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if results == nil {
		results = []models.PlaybookStepResult{}
	}
	c.JSON(200, results)
}
