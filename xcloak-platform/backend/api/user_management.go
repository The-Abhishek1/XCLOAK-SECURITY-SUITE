package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetUsers — GET /api/users (admin only)
func GetUsers(c *gin.Context) {

	users, err := repositories.GetAllUsers(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if users == nil {
		users = []models.User{}
	}

	c.JSON(200, users)
}

// InviteUserHandler — POST /api/users/invite (admin only)
// Body: { "username": "...", "email": "...", "role": "analyst" }
// Creates the user in the caller's tenant and emails them a set-password link.
func InviteUserHandler(c *gin.Context) {

	var body struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Username == "" || body.Email == "" || body.Role == "" {
		c.JSON(400, gin.H{"error": "username, email, and role are required"})
		return
	}

	err := services.InviteUser(body.Username, body.Email, body.Role, tenantIDFromContext(c))
	if err == nil {
		c.JSON(200, gin.H{"message": "Invite sent to " + body.Email})
		return
	}

	// SMTP not configured — fall back to returning a copyable link.
	if strings.Contains(err.Error(), "SMTP not configured") {
		link, linkErr := services.InviteUserGetLink(body.Username, body.Email, body.Role, tenantIDFromContext(c))
		if linkErr != nil {
			c.JSON(400, gin.H{"error": linkErr.Error()})
			return
		}
		c.JSON(200, gin.H{
			"invite_link": link,
			"message":     "SMTP not configured — share this link with " + body.Username,
		})
		return
	}

	c.JSON(400, gin.H{"error": err.Error()})
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

	if !services.IsValidRole(body.Role, tenantIDFromContext(c)) {
		c.JSON(400, gin.H{"error": "invalid role — must be admin, analyst, viewer, or an existing custom role"})
		return
	}

	if err := repositories.UpdateUserRole(id, body.Role, tenantIDFromContext(c)); err != nil {
		if err == repositories.ErrUserNotFound {
			c.JSON(404, gin.H{"error": "user not found"})
			return
		}
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

	if err := repositories.SetUserActive(id, body.Active, tenantIDFromContext(c)); err != nil {
		if err == repositories.ErrUserNotFound {
			c.JSON(404, gin.H{"error": "user not found"})
			return
		}
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

	if err := repositories.DeleteUser(id, tenantIDFromContext(c)); err != nil {
		if err == repositories.ErrUserNotFound {
			c.JSON(404, gin.H{"error": "user not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	services.LogEvent("DELETE_USER", strconv.Itoa(id), "admin")

	c.JSON(200, gin.H{"message": "User deleted"})
}
