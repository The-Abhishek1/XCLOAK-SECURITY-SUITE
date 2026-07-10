package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

// GetHashEnrichment enriches a file hash (MD5/SHA1/SHA256) against
// VirusTotal and MalwareBazaar and returns a combined verdict.
// GET /api/enrich/hash/:hash
func GetHashEnrichment(c *gin.Context) {
	hash := strings.TrimSpace(c.Param("hash"))
	if hash == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "hash required"})
		return
	}

	result, err := services.EnrichHash(hash)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

// PatchIOCShareable sets the shareable flag on a tenant's IOC so it will be
// included in the cross-tenant platform propagation cycle.
// PATCH /api/iocs/:id/shareable
func PatchIOCShareable(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	iocID, err := strconv.Atoi(c.Param("id"))
	if err != nil || iocID <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid ioc id"})
		return
	}

	var body struct {
		Shareable bool `json:"shareable"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	if err := services.MarkIOCShareable(iocID, tenantID, body.Shareable); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"shareable": body.Shareable})
}

// PatchTenantIOCSharing enables or disables a tenant's participation in the
// platform-wide threat intelligence sharing network.
// PATCH /api/settings/ioc-sharing
func PatchTenantIOCSharing(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	var body struct {
		Enabled bool `json:"ioc_sharing_enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	if err := services.SetTenantIOCSharingEnabled(tenantID, body.Enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ioc_sharing_enabled": body.Enabled})
}
