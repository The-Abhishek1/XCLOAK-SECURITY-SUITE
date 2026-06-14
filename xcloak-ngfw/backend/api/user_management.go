package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// GetUsers — GET /api/users (admin only)
func GetUsers(c *gin.Context) {

	users, err := repositories.GetAllUsers()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if users == nil {
		users = []models.User{}
	}

	c.JSON(200, users)
}

// UpdateUserRole — PUT /api/users/:id/role
// Body: { "role": "analyst" }
func UpdateUserRole(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid user id"})
		return
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	validRoles := map[string]bool{"admin": true, "analyst": true, "viewer": true}
	if !validRoles[body.Role] {
		c.JSON(400, gin.H{"error": "invalid role — must be admin, analyst, or viewer"})
		return
	}

	if err := repositories.UpdateUserRole(id, body.Role); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("UPDATE_USER_ROLE", strconv.Itoa(id)+" -> "+body.Role, "admin")

	c.JSON(200, gin.H{"message": "Role updated"})
}

// ToggleUserActive — PATCH /api/users/:id/toggle
func ToggleUserActive(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid user id"})
		return
	}

	var body struct {
		Active bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := repositories.SetUserActive(id, body.Active); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "User status updated"})
}

// DeleteUser — DELETE /api/users/:id (admin only)
func DeleteUser(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid user id"})
		return
	}

	// Prevent self-deletion
	callerID, _ := c.Get("user_id")
	if callerID != nil {
		if cid, ok := callerID.(float64); ok && int(cid) == id {
			c.JSON(400, gin.H{"error": "cannot delete your own account"})
			return
		}
	}

	if err := repositories.DeleteUser(id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("DELETE_USER", strconv.Itoa(id), "admin")

	c.JSON(200, gin.H{"message": "User deleted"})
}
