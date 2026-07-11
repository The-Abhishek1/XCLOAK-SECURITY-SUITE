package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// GetLogSources — GET /api/log-sources
func GetLogSources(c *gin.Context) {
	sources, err := repositories.GetLogSources(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if sources == nil {
		sources = []models.LogSource{}
	}
	c.JSON(http.StatusOK, sources)
}

// CreateLogSource — POST /api/log-sources
//
// Request body:
//
//	{
//	  "name": "PA-FW-01",
//	  "source_type": "syslog",   // "syslog" | "http"
//	  "ip_address":  "10.0.0.1", // required for syslog
//	  "format":      "auto",     // optional
//	  "device_type": "palo_alto" // optional
//	}
//
// For HTTP sources the response includes "api_key" (only shown once).
func CreateLogSource(c *gin.Context) {
	var body struct {
		Name       string `json:"name"       binding:"required"`
		SourceType string `json:"source_type" binding:"required"`
		IPAddress  string `json:"ip_address"`
		Format     string `json:"format"`
		DeviceType string `json:"device_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.SourceType != "syslog" && body.SourceType != "http" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_type must be 'syslog' or 'http'"})
		return
	}
	// Blank ip_address for syslog = wildcard (match any sender IP).

	format := body.Format
	if format == "" {
		format = "auto"
	}

	src := &models.LogSource{
		TenantID:   tenantIDFromContext(c),
		Name:       body.Name,
		SourceType: body.SourceType,
		IPAddress:  body.IPAddress,
		Format:     format,
		DeviceType: body.DeviceType,
		Enabled:    true,
	}

	id, plaintextKey, err := repositories.CreateLogSource(src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	src.ID = id
	src.APIKey = plaintextKey // non-empty only for http sources

	c.JSON(http.StatusCreated, src)
}

// UpdateLogSource — PUT /api/log-sources/:id
func UpdateLogSource(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var body struct {
		Name       string `json:"name"`
		DeviceType string `json:"device_type"`
		Enabled    *bool  `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if body.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enabled field is required"})
		return
	}

	if err := repositories.UpdateLogSource(id, tenantIDFromContext(c), body.Name, body.DeviceType, *body.Enabled); err != nil {
		if err.Error() == "not found" {
			c.JSON(http.StatusNotFound, gin.H{"error": "log source not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Clear the caches so the next event picks up the new state.
	repositories.InvalidateLogSourceCaches("", "")

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// DeleteLogSource — DELETE /api/log-sources/:id
func DeleteLogSource(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := repositories.DeleteLogSource(id, tenantIDFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
