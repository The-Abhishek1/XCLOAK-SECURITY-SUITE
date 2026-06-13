package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// UpdatePlaybook updates an existing playbook.
// Route: PUT /api/playbooks/:id
func UpdatePlaybook(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid playbook id"})
		return
	}

	var playbook models.Playbook
	if err := c.ShouldBindJSON(&playbook); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := repositories.UpdatePlaybook(id, playbook); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("UPDATE_PLAYBOOK", playbook.Name, "admin")

	c.JSON(200, gin.H{"message": "Playbook Updated"})
}

// DeletePlaybook deletes a playbook and its actions.
// Route: DELETE /api/playbooks/:id
func DeletePlaybook(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid playbook id"})
		return
	}

	if err := repositories.DeletePlaybook(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("DELETE_PLAYBOOK", c.Param("id"), "admin")

	c.JSON(200, gin.H{"message": "Playbook Deleted"})
}

// EnablePlaybook sets enabled = true.
// Route: PATCH /api/playbooks/:id/enable
func EnablePlaybook(c *gin.Context) {
	togglePlaybook(c, true)
}

// DisablePlaybook sets enabled = false.
// Route: PATCH /api/playbooks/:id/disable
func DisablePlaybook(c *gin.Context) {
	togglePlaybook(c, false)
}

func togglePlaybook(c *gin.Context, enabled bool) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid playbook id"})
		return
	}

	if err := repositories.SetPlaybookEnabled(id, enabled); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	msg := "Playbook Disabled"
	if enabled {
		msg = "Playbook Enabled"
	}

	c.JSON(200, gin.H{"message": msg})
}
