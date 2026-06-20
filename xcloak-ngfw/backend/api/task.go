package api

import (
	"strconv"

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

	// task.AgentID comes straight from the request body — without this
	// check, any authenticated user (any role) could dispatch any task
	// type, including destructive ones, to an agent outside their tenant.
	if !agentOwnedBy404(c, strconv.Itoa(task.AgentID)) {
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

	// RequireAgentAuth() only proves the bearer token is valid for SOME
	// agent — without this check, that agent's token could poll (and
	// receive/execute) any other agent's queued tasks, including
	// destructive SOAR actions, by changing the :id in the URL.
	if authedID, exists := c.Get("agent_id"); exists {
		if authedIDInt, ok := authedID.(int); ok {
			if requestedID, err := strconv.Atoi(agentID); err != nil || requestedID != authedIDInt {
				c.JSON(403, gin.H{"error": "cannot fetch another agent's tasks"})
				return
			}
		}
	}

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

	// Scope completion to the authenticated agent — without this, any
	// agent's token could submit a fabricated result for any other
	// agent's task_id, including destructive SOAR actions.
	agentID, _ := c.Get("agent_id")
	agentIDInt, _ := agentID.(int)

	err := services.CompleteTask(
		result.TaskID,
		result.Result,
		agentIDInt,
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
