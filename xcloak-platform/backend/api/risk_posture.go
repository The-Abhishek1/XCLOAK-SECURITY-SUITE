package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

// GetRiskPosture — GET /api/risk-posture
// Returns the most-recent snapshot; triggers a fresh computation if none
// exists or the latest snapshot is more than 1 hour old.
func GetRiskPosture(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	history, err := services.GetRiskPostureHistory(tenantID, 1)
	if err != nil || len(history) == 0 || time.Since(history[0].SnapshotAt) > time.Hour {
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
