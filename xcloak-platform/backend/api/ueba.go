package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GetUEBAUsers — GET /api/ueba/users
func GetUEBAUsers(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	profiles, total, err := repositories.GetUserRiskProfiles(tenantID, limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"profiles": profiles, "total": total})
}

// GetUEBAEvents — GET /api/ueba/events?username=&limit=&offset=
func GetUEBAEvents(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	username := c.Query("username")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	events, total, err := repositories.GetUEBAEvents(tenantID, username, limit, offset)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"events": events, "total": total})
}

// TriggerUEBAAnalysis — POST /api/ueba/analyze
func TriggerUEBAAnalysis(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	go services.AnalyzeTenant(tenantID)
	c.JSON(http.StatusOK, gin.H{"message": "UEBA analysis started"})
}
