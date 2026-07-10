package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetPermissionsHandler — GET /api/permissions (any authenticated user;
// just the fixed taxonomy, not sensitive) — drives the frontend's
// permission-checkbox UI so the list never has to be hardcoded twice.
func GetPermissionsHandler(c *gin.Context) {
	c.JSON(200, services.AllPermissions)
}

// CreateCustomRoleHandler — POST /api/custom-roles (admin only)
func CreateCustomRoleHandler(c *gin.Context) {

	var body struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	role, err := services.CreateCustomRole(tenantIDFromContext(c), body.Name, body.Permissions, username.(string))
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, role)
}

// GetCustomRolesHandler — GET /api/custom-roles (admin only)
func GetCustomRolesHandler(c *gin.Context) {

	roles, err := services.GetCustomRoles(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if roles == nil {
		roles = []models.CustomRole{}
	}

	c.JSON(200, roles)
}

// UpdateCustomRoleHandler — PUT /api/custom-roles/:id (admin only)
func UpdateCustomRoleHandler(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid role id"})
		return
	}

	var body struct {
		Permissions []string `json:"permissions"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	username, _ := c.Get("username")
	if err := services.UpdateCustomRole(id, tenantIDFromContext(c), body.Permissions, username.(string)); err != nil {
		if err == repositories.ErrCustomRoleNotFound {
			c.JSON(404, gin.H{"error": "role not found"})
			return
		}
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "role updated"})
}

// DeleteCustomRoleHandler — DELETE /api/custom-roles/:id (admin only)
func DeleteCustomRoleHandler(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid role id"})
		return
	}

	username, _ := c.Get("username")
	if err := services.DeleteCustomRole(id, tenantIDFromContext(c), username.(string)); err != nil {
		if err == repositories.ErrCustomRoleNotFound {
			c.JSON(404, gin.H{"error": "role not found"})
			return
		}
		if err == repositories.ErrCustomRoleInUse {
			c.JSON(409, gin.H{"error": "this role is still assigned to one or more users — reassign them first"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "role deleted"})
}
