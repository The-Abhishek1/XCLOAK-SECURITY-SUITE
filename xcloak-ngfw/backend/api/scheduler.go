package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// GetScheduledTasks — GET /api/scheduler/tasks
func GetScheduledTasks(c *gin.Context) {
	tasks, err := services.GetScheduledTasks(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if tasks == nil {
		tasks = []models.ScheduledTask{}
	}
	c.JSON(200, tasks)
}

// CreateScheduledTask — POST /api/scheduler/tasks
func CreateScheduledTask(c *gin.Context) {
	var st models.ScheduledTask
	if err := c.ShouldBindJSON(&st); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	st.CreatedBy = username.(string)

	created, err := services.CreateScheduledTask(st, tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, created)
}

// ToggleScheduledTask — PATCH /api/scheduler/tasks/:id/toggle
func ToggleScheduledTask(c *gin.Context) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	c.ShouldBindJSON(&body)

	if err := services.ToggleScheduledTask(c.Param("id"), body.Enabled, tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "updated"})
}

// RunScheduledTaskNow — POST /api/scheduler/tasks/:id/run
func RunScheduledTaskNow(c *gin.Context) {
	if err := services.RunScheduledTaskNow(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "dispatched"})
}

// DeleteScheduledTask — DELETE /api/scheduler/tasks/:id
func DeleteScheduledTask(c *gin.Context) {
	if err := services.DeleteScheduledTask(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}

// GetDashboardMetrics — GET /api/dashboard/metrics
func GetDashboardMetrics(c *gin.Context) {
	metrics, err := services.GetDashboardMetrics(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, metrics)
}
