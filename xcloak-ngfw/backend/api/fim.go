package api

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

// ReceiveFIMScan — POST /api/agents/fim
func ReceiveFIMScan(c *gin.Context) {

	var payload models.FIMScanPayload

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := services.ProcessFIMScan(payload); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "FIM scan processed"})
}

// GetFIMBaseline — GET /api/agents/:id/fim/baseline
func GetFIMBaseline(c *gin.Context) {

	agentID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid agent id"})
		return
	}
	if !agentOwnedBy404(c, c.Param("id")) {
		return
	}

	baseline, err := repositories.GetFIMBaseline(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if baseline == nil {
		baseline = []models.FIMBaseline{}
	}

	c.JSON(200, baseline)
}

// GetFIMAlerts — GET /api/agents/:id/fim/alerts
func GetFIMAlerts(c *gin.Context) {

	agentID := c.Param("id")
	if !agentOwnedBy404(c, agentID) {
		return
	}

	alerts, err := repositories.GetFIMAlerts(agentID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if alerts == nil {
		alerts = []models.FIMAlert{}
	}

	c.JSON(200, alerts)
}

// GetMITREMappings — GET /api/mitre/mappings
func GetMITREMappings(c *gin.Context) {

	mappings, err := services.GetMITREMappings()
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	if mappings == nil {
		mappings = []map[string]string{}
	}

	c.JSON(200, mappings)
}

// suppress unused
var _ = fmt.Sprintf
