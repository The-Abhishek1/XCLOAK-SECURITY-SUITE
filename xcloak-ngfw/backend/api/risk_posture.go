package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// GetRiskPosture — GET /api/risk-posture
// Returns the most-recent snapshot; triggers a fresh one if none exists or >1h old.
func GetRiskPosture(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	history, err := services.GetRiskPostureHistory(tenantID, 1)
	if err != nil || len(history) == 0 {
		// No snapshot yet — compute one now.
		snap, err2 := services.ComputeRiskPosture(tenantID)
		if err2 != nil {
			c.JSON(500, gin.H{"error": err2.Error()})
			return
		}
		c.JSON(http.StatusOK, snap)
		return
	}
	c.JSON(http.StatusOK, history[0])
}

// GetRiskPostureHistory — GET /api/risk-posture/history
func GetRiskPostureHistoryHandler(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "30"))
	history, err := services.GetRiskPostureHistory(tenantID, limit)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if history == nil {
		history = []models.RiskPostureSnapshot{}
	}
	c.JSON(http.StatusOK, history)
}

// RefreshRiskPosture — POST /api/risk-posture/refresh
func RefreshRiskPosture(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	snap, err := services.ComputeRiskPosture(tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, snap)
}
