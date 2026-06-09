package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func CreateTask(c *gin.Context) {

	var task models.AgentTask

	if err := c.ShouldBindJSON(&task); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.CreateTask(task)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Task Created",
	})
}

func GetAgentTasks(c *gin.Context) {

	agentID := c.Param("id")

	tasks, err := services.GetPendingTasks(agentID)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"count": len(tasks),
		"tasks": tasks,
	})
}

func SubmitTaskResult(c *gin.Context) {

	var result models.TaskResult

	if err := c.ShouldBindJSON(&result); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.CompleteTask(
		result.TaskID,
		result.Result,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "Result Received",
	})
}
