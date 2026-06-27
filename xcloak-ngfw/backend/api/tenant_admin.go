package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// CreateTenantHandler — POST /api/platform/tenants (platform admin only)
// Body: { "name": "...", "slug": "...", "admin_username": "...", "admin_email": "..." }
// Creates the tenant and invites its first admin via the existing
// password-reset-token email flow.
func CreateTenantHandler(c *gin.Context) {

	var body struct {
		Name          string `json:"name"`
		Slug          string `json:"slug"`
		AdminUsername string `json:"admin_username"`
		AdminEmail    string `json:"admin_email"`
	}

	if err := c.ShouldBindJSON(&body); err != nil ||
		body.Name == "" || body.Slug == "" || body.AdminUsername == "" || body.AdminEmail == "" {
		c.JSON(400, gin.H{"error": "name, slug, admin_username, and admin_email are required"})
		return
	}

	tenant, err := services.CreateTenant(body.Name, body.Slug, body.AdminUsername, body.AdminEmail)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"message": "tenant created — invite sent to " + body.AdminEmail,
		"tenant":  tenant,
	})
}

// GetTenantsHandler — GET /api/platform/tenants (platform admin only)
func GetTenantsHandler(c *gin.Context) {

	tenants, err := services.GetTenants()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if tenants == nil {
		tenants = []models.Tenant{}
	}

	c.JSON(200, tenants)
}

// ToggleTenantActiveHandler — PATCH /api/platform/tenants/:id/toggle
// (platform admin only)
// Body: { "is_active": true|false }
func ToggleTenantActiveHandler(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid tenant id"})
		return
	}

	var body struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if err := services.SetTenantActive(id, body.IsActive); err != nil {
		if err == repositories.ErrTenantNotFound {
			c.JSON(404, gin.H{"error": "tenant not found"})
			return
		}
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	msg := "tenant suspended"
	if body.IsActive {
		msg = "tenant reactivated"
	}
	c.JSON(200, gin.H{"message": msg})
}

// GetTenantDomains — GET /api/platform/tenants/:id/domains (platform admin)
func GetTenantDomains(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid tenant id"})
		return
	}
	domains, err := repositories.GetTenantDomains(id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if domains == nil {
		domains = []repositories.TenantDomain{}
	}
	c.JSON(200, domains)
}

// AddTenantDomain — POST /api/platform/tenants/:id/domains (platform admin)
// Body: { "domain": "acme.com" }
func AddTenantDomain(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid tenant id"})
		return
	}
	var body struct {
		Domain string `json:"domain"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Domain == "" {
		c.JSON(400, gin.H{"error": "domain is required"})
		return
	}
	if err := repositories.AddTenantDomain(id, body.Domain); err != nil {
		c.JSON(409, gin.H{"error": "domain already mapped to a tenant"})
		return
	}
	c.JSON(200, gin.H{"message": "domain added"})
}

// DeleteTenantDomain — DELETE /api/platform/tenants/:id/domains/:did (platform admin)
func DeleteTenantDomain(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid tenant id"})
		return
	}
	did, err := strconv.Atoi(c.Param("did"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid domain id"})
		return
	}
	if err := repositories.DeleteTenantDomain(did, id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "domain removed"})
}
